from __future__ import annotations

import ipaddress
import os
from urllib.parse import quote, urlparse, urlunparse
from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class SSRFPayload:
    value: str
    attack_type: str
    risk_level: str
    expected_signature: str | None = None


def _load_ssrf_payload_file(file_path: str) -> list[SSRFPayload]:
    payloads: list[SSRFPayload] = []
    if not os.path.exists(file_path):
        return payloads

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "||" not in line:
                continue

            # value || attack_type || risk_level || expected_signature(optional)
            parts = line.split("||")
            if len(parts) < 3:
                continue

            value = parts[0].strip()
            attack_type = parts[1].strip()
            risk_level = parts[2].strip()
            expected_signature = parts[3].strip() if len(parts) >= 4 else ""

            payloads.append(
                SSRFPayload(
                    value=value,
                    attack_type=attack_type,
                    risk_level=risk_level,
                    expected_signature=expected_signature or None,
                )
            )

    return payloads


def _split_host_port(netloc: str) -> tuple[str, str]:
    if not netloc:
        return "", ""
    if netloc.startswith("["):
        end = netloc.find("]")
        if end == -1:
            return netloc, ""
        host = netloc[: end + 1]
        port = netloc[end + 1 :]
        return host, port
    if ":" in netloc:
        host, port = netloc.rsplit(":", 1)
        if port.isdigit():
            return host, f":{port}"
    return netloc, ""


def _apply_ssrf_bypass(payload: SSRFPayload, bypass_level: int) -> list[SSRFPayload]:
    normalized_level = max(0, min(int(bypass_level), 2))
    if normalized_level <= 0:
        return [payload]

    mutated: list[SSRFPayload] = [payload]
    value = payload.value
    try:
        parsed = urlparse(value)
    except ValueError:
        # Keep malformed/template payloads as-is (e.g., placeholders in OOB set).
        return mutated
    if not parsed.scheme or not parsed.netloc:
        return mutated

    # Level 1: encode only path/query to preserve URL structure.
    if normalized_level >= 1:
        encoded_path = quote(parsed.path or "", safe="/%")
        encoded_query = quote(parsed.query or "", safe="=&%")
        if encoded_path != parsed.path or encoded_query != parsed.query:
            mutated.append(
                SSRFPayload(
                    value=urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            encoded_path,
                            parsed.params,
                            encoded_query,
                            parsed.fragment,
                        )
                    ),
                    attack_type=f"{payload.attack_type}_path_encode",
                    risk_level=payload.risk_level,
                    expected_signature=payload.expected_signature,
                )
            )

    # Level 2: host obfuscation for IPv4 targets (decimal/hex).
    if normalized_level >= 2:
        host, port = _split_host_port(parsed.netloc)
        normalized_host = host.strip("[]")
        try:
            ip_obj = ipaddress.ip_address(normalized_host)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                numeric = int(ip_obj)
                decimal_host = str(numeric)
                hex_host = hex(numeric)
                for obf_host, suffix in ((decimal_host, "ip_decimal"), (hex_host, "ip_hex")):
                    mutated.append(
                        SSRFPayload(
                            value=urlunparse(
                                (
                                    parsed.scheme,
                                    f"{obf_host}{port}",
                                    parsed.path,
                                    parsed.params,
                                    parsed.query,
                                    parsed.fragment,
                                )
                            ),
                            attack_type=f"{payload.attack_type}_{suffix}",
                            risk_level=payload.risk_level,
                            expected_signature=payload.expected_signature,
                        )
                    )
        except ValueError:
            pass

    return mutated


def get_ssrf_payloads(
    include_oob_templates: bool = False,
    bypass_level: int = 0,
) -> list[SSRFPayload]:
    inband_path = os.path.join("config", "payloads", "ssrf", "ssrf_inband.txt")
    oob_path = os.path.join("config", "payloads", "ssrf", "ssrf_oob_template.txt")
    fallback_path = os.path.join("config", "payloads", "ssrf", "ssrf.txt")

    # Prefer split files; fallback keeps backward compatibility.
    payloads = _load_ssrf_payload_file(inband_path)
    if not payloads:
        payloads = _load_ssrf_payload_file(fallback_path)

    if include_oob_templates:
        payloads.extend(_load_ssrf_payload_file(oob_path))
    seen: set[str] = set()
    expanded: list[SSRFPayload] = []
    for payload in payloads:
        for candidate in _apply_ssrf_bypass(payload, bypass_level=bypass_level):
            if candidate.value in seen:
                continue
            seen.add(candidate.value)
            expanded.append(candidate)
    return expanded
