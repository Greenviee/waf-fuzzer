"""
Mock parser that emits DVWA attack surfaces to the fuzzer engine.

This simulates parser/crawler streaming behavior before the real parser is ready.
"""

from __future__ import annotations

import asyncio
from typing import Any

from core import AttackSurface, HttpMethod, ParamLocation


def get_dvwa_mock_surfaces(
    base_url: str,
    cookies: dict[str, str] | None = None,
) -> list[AttackSurface]:
    """
    Build representative DVWA attack surfaces for integration testing.
    """
    root = base_url.rstrip("/")
    auth_cookies = cookies or {}

    return [
        # AttackSurface(
        #     url=f"{root}/vulnerabilities/xss_r/",
        #     method=HttpMethod.GET,
        #     param_location=ParamLocation.QUERY,
        #     parameters={"name": "tester"},
        #     cookies=auth_cookies,
        #     description="DVWA Reflected XSS (GET)",
        # ),
        # AttackSurface(
        #     url=f"{root}/vulnerabilities/xss_s/",
        #     method=HttpMethod.POST,
        #     param_location=ParamLocation.BODY_FORM,
        #     parameters={"txtName": "tester", "mtxMessage": "hello", "btnSign": "Sign Guestbook"},
        #     cookies=auth_cookies,
        #     description="DVWA Stored XSS (POST)",
        # ),
        # AttackSurface(
        #     url=f"{root}/vulnerabilities/exec/",
        #     method=HttpMethod.POST,
        #     param_location=ParamLocation.BODY_FORM,
        #     parameters={"ip": "127.0.0.1", "Submit": "Submit"},
        #     cookies=auth_cookies,
        #     description="DVWA Command Injection (POST)",
        # ),
        # AttackSurface(
        #     url=f"{root}/vulnerabilities/csrf/",
        #     method=HttpMethod.GET,
        #     param_location=ParamLocation.QUERY,
        #     parameters={"password_new": "123456", "password_conf": "123456", "Change": "Change"},
        #     cookies=auth_cookies,
        #     description="DVWA CSRF (GET)",
        # ),
        # AttackSurface(
        #     url=f"{root}/vulnerabilities/fi/",
        #     method=HttpMethod.GET,
        #     param_location=ParamLocation.QUERY,
        #     parameters={"page": "include.php"},
        #     cookies=auth_cookies,
        #     description="DVWA File Inclusion (GET)",
        # ),
        # AttackSurface(
        #     url=f"{root}/vulnerabilities/brute/",
        #     method=HttpMethod.GET,
        #     param_location=ParamLocation.QUERY,
        #     parameters={
        #         "username": "admin",
        #         "password": "password",
        #         "Login": "Login",
        #         "user_token": "",
        #     },
        #     cookies=auth_cookies,
        #     description="DVWA Brute Force (GET, with CSRF token)",
        #     dynamic_tokens=["user_token"],
        # ),
        AttackSurface(
            url=f"{root}/vulnerabilities/brute/",
            method=HttpMethod.GET,
            param_location=ParamLocation.QUERY,
            parameters={
                "username": "admin",
                "password": "password",
                "Login": "Login",
            },
            cookies=auth_cookies,
            description="DVWA Brute Force (GET, no CSRF token)",
        ),
        # AttackSurface(
        #     url=f"{root}/vulnerabilities/sqli/",
        #     method=HttpMethod.GET,
        #     param_location=ParamLocation.QUERY,
        #     parameters={"id": "1", "Submit": "Submit"},
        #     cookies=auth_cookies,
        #     description="DVWA SQL Injection (GET)",
        # ),
        # AttackSurface(
        #     url=f"{root}/vulnerabilities/upload/",
        #     method=HttpMethod.POST,
        #     # Multipart is represented as form data in current request builder.
        #     param_location=ParamLocation.BODY_FORM,
        #     parameters={
        #         "MAX_FILE_SIZE": "100000",
        #         "uploaded": "",
        #         "Upload": "Upload",
        #     },
        #     cookies=auth_cookies,
        #     description="DVWA File Upload (POST)",
        # ),
        # AttackSurface(
        #     url=f"{root}/vulnerabilities/sqli_blind/",
        #     param_location=ParamLocation.QUERY,
        #     parameters={"id": "1", "Submit": "Submit"},
        #     cookies=auth_cookies,
        #     description="DVWA Blind SQLi (GET)",
        # ),
        # AttackSurface(
        #     url=f"{root}/vulnerabilities/upload/",
        #     method=HttpMethod.POST,
        #     # Multipart is represented as form data in current request builder.
        #     param_location=ParamLocation.BODY_FORM,
        #     parameters={"uploaded": "file_content_here", "Upload": "Upload"},
        #     cookies=auth_cookies,
        #     description="DVWA File Upload (POST)",
        # ),
        # AttackSurface(
        #     url=f"{root}/vulnerabilities/xss_d/",
        #     method=HttpMethod.GET,
        #     param_location=ParamLocation.QUERY,
        #     parameters={"default": "English"},
        #     cookies=auth_cookies,
        #     description="DVWA DOM XSS (GET)",
        # ),
        # AttackSurface(
        #     url=f"{root}/test_ssrf.php/",
        #     method=HttpMethod.GET,
        #     param_location=ParamLocation.QUERY,
        #     parameters={"url": "http://example.com"},
        #     cookies=auth_cookies,
        #     description="DVWA SSRF(GET)",
        # ),
    ]


async def run_mock_parser(
    engine: Any,
    *,
    base_url: str,
    cookies: dict[str, str] | None = None,
    emit_delay: float = 0.05,
    verbose: bool = False,
) -> int:
    """
    Simulate parser streaming: emit AttackSurface items one by one into engine queues.
    """
    surfaces = get_dvwa_mock_surfaces(base_url=base_url, cookies=cookies)
    if verbose:
        print(f"[mock-parser] discovered {len(surfaces)} attack surfaces")

    for index, surface in enumerate(surfaces, start=1):
        await asyncio.sleep(max(0.0, emit_delay))
        if verbose:
            print(
                f"[mock-parser] emit {index}/{len(surfaces)}: "
                f"{surface.method.value} {surface.url} ({surface.param_location.value})"
            )
        await engine.submit_surface(surface)

    if verbose:
        print("[mock-parser] all attack surfaces emitted")
    return len(surfaces)
