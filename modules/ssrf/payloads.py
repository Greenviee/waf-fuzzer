from __future__ import annotations

import os
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


def get_ssrf_payloads(include_oob_templates: bool = False) -> list[SSRFPayload]:
    inband_path = os.path.join("config", "payloads", "ssrf_inband.txt")
    oob_path = os.path.join("config", "payloads", "ssrf_oob_template.txt")
    fallback_path = os.path.join("config", "payloads", "ssrf.txt")

    # Prefer split files; fallback keeps backward compatibility.
    payloads = _load_ssrf_payload_file(inband_path)
    if not payloads:
        payloads = _load_ssrf_payload_file(fallback_path)

    if include_oob_templates:
        payloads.extend(_load_ssrf_payload_file(oob_path))

    return payloads
