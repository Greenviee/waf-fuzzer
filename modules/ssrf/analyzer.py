from __future__ import annotations

import re

_CLOUD_TARGET_HINTS = (
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    "192.0.0.192",
    "169.254.170.2",
)
_CLOUD_SUCCESS_HINTS = (
    "ami-id",
    "instance-id",
    "local-ipv4",
    "accesskeyid",
    "secretaccesskey",
    "computemetadata",
    "x-aws-ec2-metadata-token",
    "metadata-flavor",
)
_CLOUD_ERROR_HINTS = (
    "metadata-flavor",
    "aws-ec2-metadata",
    "required header",
    "x-aws-ec2-metadata-token",
)
_INTERNAL_NETWORK_ERROR_HINTS = (
    "connection refused",
    "no route to host",
    "name or service not known",
    "network is unreachable",
    "connection timed out",
    "ssh-2.0",
    "redis_version",
)
_LOCALHOST_TARGET_HINTS = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "::1",
)
_LOGIN_PAGE_HINTS = (
    "login",
    "sign in",
    "username",
    "password",
    "remember me",
)
_BLIND_PROBE_HINTS = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "::1",
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.2",
    "172.30.",
    "172.31.",
    "192.168.",
    "169.254.",
    "file://",
)


def _extract_response_text(response) -> str:
    if isinstance(response, str):
        return response
    text_attr = getattr(response, "text", "")
    if callable(text_attr):
        try:
            return str(text_attr())
        except Exception:
            return str(response)
    return str(text_attr or "")


def _extract_status_code(response) -> int:
    status_code = getattr(response, "status_code", None)
    if status_code is not None:
        return int(status_code)
    status = getattr(response, "status", None)
    if status is not None:
        return int(status)
    return 0


def _status_class(status_code: int) -> int:
    if status_code <= 0:
        return 0
    return status_code // 100


def _is_blind_probe_payload(payload_value_lower: str) -> bool:
    return any(hint in payload_value_lower for hint in _BLIND_PROBE_HINTS)


def analyze_ssrf(response, payload, elapsed_time: float, original_res=None) -> bool:
    res_text = _extract_response_text(response)
    res_text_lower = res_text.lower()
    original_text = _extract_response_text(original_res) if original_res is not None else ""
    original_text_lower = original_text.lower()
    status_code = _extract_status_code(response)
    original_status_code = _extract_status_code(original_res) if original_res is not None else 0
    expected_signature = getattr(payload, "expected_signature", None)
    payload_value = str(getattr(payload, "value", ""))
    payload_value_lower = payload_value.lower()

    # 1) Strong signature match (best signal, keep highest priority)
    if expected_signature:
        try:
            matched_current = bool(re.search(expected_signature, res_text, re.IGNORECASE | re.DOTALL))
            matched_original = bool(
                original_text and re.search(expected_signature, original_text, re.IGNORECASE | re.DOTALL)
            )
            if matched_current and not matched_original:
                return True
        except re.error:
            expected_lower = expected_signature.lower()
            if expected_lower in res_text_lower and expected_lower not in original_text_lower:
                return True

    # 2) Cloud metadata endpoint heuristics and cloud-specific errors
    is_cloud_payload = any(hint in payload_value_lower for hint in _CLOUD_TARGET_HINTS)
    if is_cloud_payload:
        new_cloud_hints = [
            hint for hint in _CLOUD_SUCCESS_HINTS
            if hint in res_text_lower and hint not in original_text_lower
        ]
        if status_code == 200 and new_cloud_hints:
            return True
        if status_code in (400, 401, 403) and any(
            hint in res_text_lower for hint in _CLOUD_ERROR_HINTS
        ):
            return True

    # 3) Internal-network error fingerprints (port-scan style SSRF evidence)
    if any(hint in res_text_lower for hint in _INTERNAL_NETWORK_ERROR_HINTS):
        return True

    # 4) Boolean-blind style delta checks (host discovery, path brute-force, bypasses)
    is_blind_probe = _is_blind_probe_payload(payload_value_lower)
    is_cloud_payload = any(hint in payload_value_lower for hint in _CLOUD_TARGET_HINTS)

    # Cloud-target payloads are intentionally excluded from generic blind length deltas.
    # Cloud success should be confirmed by explicit cloud hints (step 2).
    if is_blind_probe and original_res is not None and not is_cloud_payload:
        # 4-1) Status class delta: e.g. baseline 2xx -> probe 4xx/5xx (or inverse)
        if _status_class(status_code) != _status_class(original_status_code):
            return True

        # 4-2) Meaningful body length delta (conservative threshold)
        len_current = len(res_text)
        len_original = len(original_text)
        if len_original > 0:
            diff_ratio = abs(len_current - len_original) / len_original
            if diff_ratio >= 0.30 and abs(len_current - len_original) >= 200:
                # Drop "empty 200 OK" style responses often caused by silent blocks/failures.
                if not (status_code == 200 and len_current < 10):
                    return True

        # 4-3) New login page hints (internal admin/login panel reachability)
        has_login_hints = any(hint in res_text_lower for hint in _LOGIN_PAGE_HINTS)
        had_login_hints = any(hint in original_text_lower for hint in _LOGIN_PAGE_HINTS)
        if has_login_hints and not had_login_hints:
            return True

    # 5) Time-based blind hints for deliberate timeout/port probes
    if ("10.255.255.255" in payload_value_lower or ":22" in payload_value_lower) and elapsed_time > 10.0:
        return True

    return False
