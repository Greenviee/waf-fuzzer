"""
Raw HTTP request file parser for targeted brute-force attacks.

Reads a raw HTTP request text file (e.g. exported from Burp Suite or captured with
a proxy), extracts all headers/cookies/parameters, and produces a single AttackSurface.

The FUZZ marker in the request body or query string marks which parameter to brute-force.
All other parameters are kept as-is and sent verbatim with every request.

Supported formats:
  GET  /path?param=value&target=FUZZ HTTP/1.1
  POST with Content-Type: application/x-www-form-urlencoded
  POST with Content-Type: application/json
"""

from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlparse

from core.models import AttackSurface, HttpMethod, ParamLocation

FUZZ_MARKER = "FUZZ"


def parse_raw_request(
    file_path: str,
    *,
    default_scheme: str = "http",
) -> AttackSurface:
    """
    Parse a raw HTTP request file into an AttackSurface.

    The file must contain a valid HTTP/1.x request in plain text.
    Lines may use CRLF or LF line endings.

    Raises:
        FileNotFoundError: if file_path does not exist.
        ValueError: if the request line or Host header is missing/malformed.
    """
    with open(file_path, "r", encoding="utf-8") as fh:
        raw = fh.read()

    # Normalise line endings to LF
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")

    header_section, body = _split_head_body(raw)
    lines = header_section.splitlines()
    if not lines:
        raise ValueError("Request file is empty.")

    method, raw_path = _parse_request_line(lines[0])
    headers, cookies, host, content_type = _parse_headers(lines[1:])

    if not host:
        raise ValueError(
            "No 'Host' header found in request file. "
            "Make sure the file contains a complete HTTP request."
        )

    url, params, param_location = _extract_params(
        method=method,
        raw_path=raw_path,
        body=body,
        content_type=content_type,
        host=host,
        scheme=default_scheme,
    )

    # Strip transport-level headers that aiohttp manages itself
    _TRANSPORT_HEADERS = {"host", "content-length", "transfer-encoding", "cookie"}
    clean_headers = {
        k: v for k, v in headers.items() if k.lower() not in _TRANSPORT_HEADERS
    }

    fuzz_params = [k for k, v in params.items() if v == FUZZ_MARKER]
    if not fuzz_params:
        raise ValueError(
            f"No '{FUZZ_MARKER}' marker found in the request parameters. "
            f"Place the literal string '{FUZZ_MARKER}' as the value of the "
            "parameter you want to brute-force."
        )

    return AttackSurface(
        url=url,
        method=method,
        param_location=param_location,
        parameters=params,
        headers=clean_headers,
        cookies=cookies,
        description=f"Raw request: {method.value} {url} [FUZZ={', '.join(fuzz_params)}]",
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _split_head_body(raw: str) -> tuple[str, str]:
    """Split raw HTTP text into header section and body on the blank line."""
    if "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        head = raw
        body = ""
    return head, body.strip()


def _parse_request_line(line: str) -> tuple[HttpMethod, str]:
    parts = line.strip().split()
    if len(parts) < 2:
        raise ValueError(f"Cannot parse request line: {line!r}")
    method_str = parts[0].upper()
    raw_path = parts[1]
    try:
        method = HttpMethod(method_str)
    except ValueError:
        # Fall back to GET for unknown verbs
        method = HttpMethod.GET
    return method, raw_path


def _parse_headers(
    lines: list[str],
) -> tuple[dict[str, str], dict[str, str], str, str]:
    """
    Returns:
        headers      - all headers as dict
        cookies      - cookie name->value dict
        host         - value of the Host header
        content_type - value of Content-Type header (lowercased)
    """
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    host = ""
    content_type = ""

    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        headers[key] = value
        key_lower = key.lower()

        if key_lower == "host":
            host = value
        elif key_lower == "content-type":
            content_type = value.lower()
        elif key_lower == "cookie":
            for part in value.split(";"):
                part = part.strip()
                if "=" in part:
                    ck, cv = part.split("=", 1)
                    cookies[ck.strip()] = cv.strip()

    return headers, cookies, host, content_type


def _extract_params(
    *,
    method: HttpMethod,
    raw_path: str,
    body: str,
    content_type: str,
    host: str,
    scheme: str,
) -> tuple[str, dict[str, str], ParamLocation]:
    """
    Determine URL, parameter dict, and ParamLocation based on method/body.
    """
    parsed = urlparse(raw_path)
    base_url = f"{scheme}://{host}{parsed.path}"

    if method == HttpMethod.GET:
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        return base_url, params, ParamLocation.QUERY

    # POST / PUT / PATCH
    if "application/json" in content_type:
        try:
            raw_json = json.loads(body) if body else {}
        except json.JSONDecodeError as exc:
            raise ValueError(f"Request body is not valid JSON: {exc}") from exc
        # Flatten one level for now; nested JSON bodies are uncommon in login forms
        params = {k: str(v) for k, v in raw_json.items()}
        return base_url, params, ParamLocation.BODY_JSON

    # Default: application/x-www-form-urlencoded
    params = dict(parse_qsl(body, keep_blank_values=True))
    return base_url, params, ParamLocation.BODY_FORM
