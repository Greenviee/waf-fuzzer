from __future__ import annotations

import asyncio
import copy
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import aiohttp

from core.models import AttackSurface, ParamLocation


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
    payload: str,
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

    if surface.param_location == ParamLocation.QUERY:
        req_params[parameter] = payload
        request_kwargs["params"] = req_params
    elif surface.param_location == ParamLocation.BODY_FORM:
        req_params[parameter] = payload
        request_kwargs["data"] = req_params
    elif surface.param_location == ParamLocation.BODY_JSON:
        req_params[parameter] = payload
        request_kwargs["json"] = req_params
    elif surface.param_location == ParamLocation.HEADER:
        headers[parameter] = payload
        if req_params:
            request_kwargs["params"] = req_params
    elif surface.param_location == ParamLocation.COOKIE:
        cookies[parameter] = payload
        if req_params:
            request_kwargs["params"] = req_params
    elif surface.param_location == ParamLocation.PATH:
        url = _inject_path_payload(url=url, parameter=parameter, payload=payload)
        if req_params:
            request_kwargs["params"] = req_params
    else:
        if req_params:
            request_kwargs["params"] = req_params

    if headers:
        request_kwargs["headers"] = headers
    if cookies:
        request_kwargs["cookies"] = cookies

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
