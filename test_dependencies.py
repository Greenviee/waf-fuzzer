"""
Temporary test hooks for module queue mode.

Replace imports in main.py with the real team modules when ready.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from core import Payload
from fuzzer import FuzzerResponse, build_and_send_request
from modules.sqli.analyzer import SQLiModule
from modules.xss.analyzer import XSSModule


def _payloads_sqli() -> list[Payload]:
    return [
        Payload(value="admin' or 1=1 #", attack_type="SQL Injection", risk_level="CRITICAL"),
        Payload(value="' UNION SELECT user, password #", attack_type="SQL Injection", risk_level="CRITICAL"),
        Payload(value="1' AND 1=2 #", attack_type="SQL Injection", risk_level="MEDIUM"),
        Payload(value="admin\\' --", attack_type="SQL Injection", risk_level="LOW"),
    ]


def _payloads_xss() -> list[Payload]:
    return [
        Payload(value="<script>alert('xss')</script>", attack_type="Cross-Site Scripting", risk_level="HIGH"),
        Payload(value="<img src=x onerror=prompt(1)>", attack_type="Cross-Site Scripting", risk_level="MEDIUM"),
    ]


def _payloads_csrf() -> list[Payload]:
    return [
        Payload(value="hacked_password", attack_type="CSRF", risk_level="HIGH"),
    ]


def _payloads_misc() -> list[Payload]:
    return [
        Payload(value="normal_user_123", attack_type="Normal Request", risk_level="LOW"),
        Payload(value="; cat /etc/passwd", attack_type="Command Injection", risk_level="CRITICAL"),
        Payload(value="../../../../etc/shadow", attack_type="Local File Inclusion", risk_level="HIGH"),
    ]


# Map CLI --type values to callables that return payloads for that attack class.
ATTACK_PAYLOAD_PROVIDERS: dict[str, Callable[[], list[Payload]]] = {
    "sqli": _payloads_sqli,
    "xss": _payloads_xss,
    "csrf": _payloads_csrf,
}


def get_payloads(attack_type: str) -> list[Payload]:
    """
    Return payloads for the given attack type.
    ``all`` merges every registered attack category (plus misc samples).
    """
    if attack_type == "all":
        merged: list[Payload] = []
        for provider in ATTACK_PAYLOAD_PROVIDERS.values():
            merged.extend(provider())
        merged.extend(_payloads_misc())
        return merged

    provider = ATTACK_PAYLOAD_PROVIDERS.get(attack_type)
    return provider() if provider else []


def is_vulnerable(response: FuzzerResponse) -> bool:
    """Analyze the HTTP response and return True if the probe looks successful."""
    if response.error == "TimeoutError":
        return True

    text = (response.text or "").lower()

    if "password changed" in text:
        return True
    if "you have an error in your sql syntax" in text or "mysql_fetch_array" in text:
        return True
    if text.count("first name:") > 1:
        return True
    if "<script>alert('xss')</script>" in text:
        return True

    return False


@dataclass(slots=True)
class CsrfModule:
    """
    Temporary CSRF module for module-queue integration tests.
    """

    name: str = "CSRF"

    def get_payloads(self) -> list[Payload]:
        return _payloads_csrf()

    def analyze(
        self,
        response: FuzzerResponse,
        payload: Payload,
        elapsed_time: float,
        original_res: FuzzerResponse | None = None,
    ) -> bool:
        del payload, elapsed_time, original_res
        text = (response.text or "").lower()
        return "password changed" in text or "csrf" in text


def get_attack_modules(attack_type: str) -> list[Any]:
    """
    Return module instances used by FuzzerEngine.run_with_attack_modules().
    """
    module_factories: dict[str, Callable[[], Any]] = {
        "sqli": SQLiModule,
        "xss": XSSModule,
        "csrf": CsrfModule,
    }

    if attack_type == "all":
        return [factory() for factory in module_factories.values()]

    factory = module_factories.get(attack_type)
    return [factory()] if factory else []


def count_module_payloads(modules: list[Any]) -> int:
    """
    Sum payload sizes across selected modules for CLI display.
    """
    return sum(len(module.get_payloads()) for module in modules)


async def verbose_request_sender(session, surface, parameter, payload):
    """Log each request, then delegate to the shared request builder."""
    payload_value = getattr(payload, "value", str(payload))
    print(f"[send] parameter={parameter!r} payload={payload_value!r}")
    return await build_and_send_request(session, surface, parameter, payload_value)
