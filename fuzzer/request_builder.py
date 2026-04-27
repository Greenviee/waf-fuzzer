from __future__ import annotations

import asyncio
import copy
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote

import aiohttp

from core.models import AttackSurface, ParamLocation


_DYNAMIC_TOKEN_LOCKS: dict[str, asyncio.Lock] = {}
_DYNAMIC_TOKEN_LOCKS_GUARD = asyncio.Lock()


@dataclass(slots=True)
class FuzzerResponse:
    """
    Normalized HTTP response passed to vulnerability checkers.
    """

    status: int
    text: str
    headers: dict[str, str]
    elapsed_time: float
    url: str
    error: str | None = None

    @property
    def elapsed(self) -> float:
        """
        Backward-compatible alias.
        Older code may still access `response.elapsed`.
        """
        return self.elapsed_time


class _TokenExtractor(HTMLParser):
    def __init__(self, targets: set[str]) -> None:
        super().__init__()
        self.targets = targets
        self.tokens: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): v for k, v in attrs if v is not None}
        name = attr_map.get("name")
        if not name or name not in self.targets:
            return

        tag_lower = tag.lower()
        if tag_lower == "input":
            value = attr_map.get("value")
            if value is not None:
                self.tokens[name] = value
        elif tag_lower == "meta":
            content = attr_map.get("content")
            if content is not None:
                self.tokens[name] = content


def _dynamic_lock_key(cookies: dict[str, Any]) -> str:
    session_id = cookies.get("PHPSESSID")
    if session_id:
        return f"phpsessid:{session_id}"
    if not cookies:
        return "no-cookie"
    parts = [f"{k}={cookies[k]}" for k in sorted(cookies.keys())]
    return "cookie:" + "|".join(parts)


async def _get_dynamic_token_lock(lock_key: str) -> asyncio.Lock:
    async with _DYNAMIC_TOKEN_LOCKS_GUARD:
        lock = _DYNAMIC_TOKEN_LOCKS.get(lock_key)
        if lock is None:
            lock = asyncio.Lock()
            _DYNAMIC_TOKEN_LOCKS[lock_key] = lock
    return lock


async def fetch_dynamic_tokens(
    session: aiohttp.ClientSession,
    surface: AttackSurface,
    *,
    headers_override: dict[str, Any] | None = None,
    cookies_override: dict[str, Any] | None = None,
) -> dict[str, str]:
    dynamic_tokens = getattr(surface, "dynamic_tokens", None) or []
    token_targets = {str(token) for token in dynamic_tokens if str(token)}
    if not token_targets:
        return {}

    headers = copy.deepcopy(headers_override) if headers_override is not None else (
        copy.deepcopy(surface.headers) if surface.headers else {}
    )
    cookies = copy.deepcopy(cookies_override) if cookies_override is not None else (
        copy.deepcopy(surface.cookies) if surface.cookies else {}
    )

    request_kwargs: dict[str, Any] = {}
    if headers:
        request_kwargs["headers"] = headers
    if cookies:
        request_kwargs["cookies"] = cookies

    try:
        async with session.get(surface.url, **request_kwargs) as response:
            html = await response.text(errors="replace")
    except Exception as exc:
        print(f"[request-builder] dynamic token refresh failed: {exc}")
        return {}

    parser = _TokenExtractor(token_targets)
    parser.feed(html)
    return parser.tokens


def _apply_dynamic_tokens(
    tokens: dict[str, str],
    *,
    attack_parameter: str | None,
    req_params: dict[str, Any],
    headers: dict[str, Any],
    cookies: dict[str, Any],
) -> None:
    for token_name, token_value in tokens.items():
        if attack_parameter is not None and token_name == attack_parameter:
            continue
        if token_name in req_params:
            req_params[token_name] = token_value
        if token_name in headers:
            headers[token_name] = token_value
        if token_name in cookies:
            cookies[token_name] = token_value


def _log_dynamic_tokens(
    *,
    surface: AttackSurface,
    attack_parameter: str | None,
    tokens: dict[str, str],
    req_params: dict[str, Any],
    headers: dict[str, Any],
    cookies: dict[str, Any],
) -> None:
    if not tokens:
        return

    mode = "baseline" if attack_parameter is None else f"attack:{attack_parameter}"
    print(f"[*] [DynamicToken] refresh on {surface.url} ({mode})")
    for token_name, extracted_value in tokens.items():
        used_value = None
        used_in = "not-applied"
        if token_name in req_params:
            used_value = req_params[token_name]
            used_in = "params"
        elif token_name in headers:
            used_value = headers[token_name]
            used_in = "headers"
        elif token_name in cookies:
            used_value = cookies[token_name]
            used_in = "cookies"
        print(
            f"    - {token_name}: extracted='{extracted_value}' "
            f"used='{used_value}' location={used_in}"
        )


async def _send_prepared_request(
    session: aiohttp.ClientSession,
    *,
    method: str,
    url: str,
    request_kwargs: dict[str, Any],
) -> FuzzerResponse:
    start_time = time.monotonic()
    try:
        async with session.request(method, url, **request_kwargs) as response:
            text = await response.text(errors="replace")
            elapsed = time.monotonic() - start_time
            return FuzzerResponse(
                status=response.status,
                text=text,
                headers=dict(response.headers),
                elapsed_time=elapsed,
                url=str(response.url),
            )
    except asyncio.TimeoutError:
        elapsed = time.monotonic() - start_time
        return FuzzerResponse(
            status=0,
            text="",
            headers={},
            elapsed_time=elapsed,
            url=url,
            error="TimeoutError",
        )
    except aiohttp.ClientError as exc:
        elapsed = time.monotonic() - start_time
        return FuzzerResponse(
            status=0,
            text="",
            headers={},
            elapsed_time=elapsed,
            url=url,
            error=f"ClientError: {exc}",
        )
    except Exception as exc:
        elapsed = time.monotonic() - start_time
        return FuzzerResponse(
            status=0,
            text="",
            headers={},
            elapsed_time=elapsed,
            url=url,
            error=f"UnknownError: {exc}",
        )


def _resolve_payload_value(payload: Any) -> str:
    if hasattr(payload, "value"):
        return str(getattr(payload, "value"))
    return str(payload)


def _is_file_payload(payload: Any) -> bool:
    return all(
        hasattr(payload, attr)
        for attr in ("filename", "content", "content_type")
    )


def _inject_path_payload(url: str, parameter: str, payload: str) -> str:
    """
    Replace a path placeholder with encoded payload.
    Supported placeholders: {id}, :id
    """
    encoded_payload = quote(payload, safe="")
    brace_token = "{" + parameter + "}"
    colon_token = ":" + parameter

    if brace_token in url:
        return url.replace(brace_token, encoded_payload)
    if colon_token in url:
        return url.replace(colon_token, encoded_payload)
    return url


async def build_and_send_request(
    session: aiohttp.ClientSession,
    surface: AttackSurface,
    parameter: str,
    payload: Any,
) -> FuzzerResponse:
    """
    Clone attack surface data, inject one payload, and send the HTTP request.
    """
    method = getattr(surface.method, "value", str(surface.method))
    url = surface.url

    req_params = copy.deepcopy(surface.parameters) if surface.parameters else {}
    headers = copy.deepcopy(surface.headers) if surface.headers else {}
    cookies = copy.deepcopy(surface.cookies) if surface.cookies else {}

    if isinstance(req_params, list):
        req_params = {str(k): "" for k in req_params}

    request_kwargs: dict[str, Any] = {}
    payload_value = _resolve_payload_value(payload)
    is_file_payload = _is_file_payload(payload)

    if surface.param_location == ParamLocation.QUERY:
        req_params[parameter] = payload_value
        request_kwargs["params"] = req_params
    elif surface.param_location == ParamLocation.BODY_FORM:
        if is_file_payload:
            form = aiohttp.FormData()
            for key, value in req_params.items():
                if key == parameter:
                    continue
                form.add_field(str(key), str(value))
            form.add_field(
                parameter,
                payload.content,
                filename=str(payload.filename),
                content_type=str(payload.content_type),
            )
            request_kwargs["data"] = form
        else:
            req_params[parameter] = payload_value
            request_kwargs["data"] = req_params
    elif surface.param_location == ParamLocation.BODY_JSON:
        req_params[parameter] = payload_value
        request_kwargs["json"] = req_params
    elif surface.param_location == ParamLocation.HEADER:
        headers[parameter] = payload_value
        if req_params:
            request_kwargs["params"] = req_params
    elif surface.param_location == ParamLocation.COOKIE:
        cookies[parameter] = payload_value
        if req_params:
            request_kwargs["params"] = req_params
    elif surface.param_location == ParamLocation.PATH:
        url = _inject_path_payload(url=url, parameter=parameter, payload=payload_value)
        if req_params:
            request_kwargs["params"] = req_params
    else:
        if req_params:
            request_kwargs["params"] = req_params

    if headers:
        request_kwargs["headers"] = headers
    if cookies:
        request_kwargs["cookies"] = cookies
    dynamic_tokens = getattr(surface, "dynamic_tokens", None) or []
    if not dynamic_tokens:
        return await _send_prepared_request(
            session,
            method=method,
            url=url,
            request_kwargs=request_kwargs,
        )

    lock_key = _dynamic_lock_key(cookies)
    token_lock = await _get_dynamic_token_lock(lock_key)
    async with token_lock:
        new_tokens = await fetch_dynamic_tokens(
            session,
            surface,
            headers_override=headers,
            cookies_override=cookies,
        )
        if new_tokens:
            _apply_dynamic_tokens(
                new_tokens,
                attack_parameter=parameter,
                req_params=req_params,
                headers=headers,
                cookies=cookies,
            )
            _log_dynamic_tokens(
                surface=surface,
                attack_parameter=parameter,
                tokens=new_tokens,
                req_params=req_params,
                headers=headers,
                cookies=cookies,
            )

        if surface.param_location == ParamLocation.QUERY and req_params:
            request_kwargs["params"] = req_params
        elif surface.param_location == ParamLocation.BODY_FORM:
            if is_file_payload:
                form = aiohttp.FormData()
                for key, value in req_params.items():
                    if key == parameter:
                        continue
                    form.add_field(str(key), str(value))
                form.add_field(
                    parameter,
                    payload.content,
                    filename=str(payload.filename),
                    content_type=str(payload.content_type),
                )
                request_kwargs["data"] = form
            else:
                request_kwargs["data"] = req_params
        elif surface.param_location == ParamLocation.BODY_JSON:
            request_kwargs["json"] = req_params
        elif req_params:
            request_kwargs["params"] = req_params
        if headers:
            request_kwargs["headers"] = headers
        if cookies:
            request_kwargs["cookies"] = cookies

        return await _send_prepared_request(
            session,
            method=method,
            url=url,
            request_kwargs=request_kwargs,
        )


async def send_baseline_request(
    session: aiohttp.ClientSession,
    surface: AttackSurface,
) -> FuzzerResponse:
    """
    Send one non-injected baseline request for comparison analyzers.
    """
    method = getattr(surface.method, "value", str(surface.method))
    url = surface.url

    req_params = copy.deepcopy(surface.parameters) if surface.parameters else {}
    headers = copy.deepcopy(surface.headers) if surface.headers else {}
    cookies = copy.deepcopy(surface.cookies) if surface.cookies else {}

    if isinstance(req_params, list):
        req_params = {str(k): "" for k in req_params}

    request_kwargs: dict[str, Any] = {}
    if req_params:
        request_kwargs["params"] = req_params
    if headers:
        request_kwargs["headers"] = headers
    if cookies:
        request_kwargs["cookies"] = cookies
    dynamic_tokens = getattr(surface, "dynamic_tokens", None) or []
    if not dynamic_tokens:
        return await _send_prepared_request(
            session,
            method=method,
            url=url,
            request_kwargs=request_kwargs,
        )

    lock_key = _dynamic_lock_key(cookies)
    token_lock = await _get_dynamic_token_lock(lock_key)
    async with token_lock:
        new_tokens = await fetch_dynamic_tokens(
            session,
            surface,
            headers_override=headers,
            cookies_override=cookies,
        )
        if new_tokens:
            _apply_dynamic_tokens(
                new_tokens,
                attack_parameter=None,
                req_params=req_params,
                headers=headers,
                cookies=cookies,
            )
            _log_dynamic_tokens(
                surface=surface,
                attack_parameter=None,
                tokens=new_tokens,
                req_params=req_params,
                headers=headers,
                cookies=cookies,
            )

        if req_params:
            request_kwargs["params"] = req_params
        if headers:
            request_kwargs["headers"] = headers
        if cookies:
            request_kwargs["cookies"] = cookies

        return await _send_prepared_request(
            session,
            method=method,
            url=url,
            request_kwargs=request_kwargs,
        )
