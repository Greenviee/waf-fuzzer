from __future__ import annotations

import copy
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal

from modules.ssrf.module import SSRF_MODULE_REPORT_NAME

_SSRF_INTERNAL_CLASS = "SSRF-Internal"


def severity_rank(raw: str) -> int:
    """Lower is more severe (critical first)."""
    key = str(raw or "").strip().lower()
    if key in ("critical", "crit"):
        return 0
    if key == "high":
        return 1
    if key in ("medium", "med"):
        return 2
    if key == "low":
        return 3
    return 4


# Evasion / encoding variants of the same logical attack (group under one finding).
_MUTATION_TYPE_SUFFIXES: tuple[str, ...] = (
    "_Double_Encoded",
    "_URL_Encoded",
    "_Null_Byte",
    "_Path_Bypass_1",
    "_Path_Bypass_2",
    "_Case_Bypass",
    "_path_encode",
    "_ip_decimal",
    "_ip_hex",
)


def canonical_attack_type_for_grouping(raw: str) -> str:
    """Strip known mutation suffixes so e.g. LFI_PHP_Wrapper_URL_Encoded -> LFI_PHP_Wrapper."""
    original = str(raw or "")
    s = original
    changed = True
    while changed:
        changed = False
        for suf in _MUTATION_TYPE_SUFFIXES:
            if s.endswith(suf):
                s = s[: -len(suf)]
                changed = True
                break
    return s if s else original


def _is_inband_ssrf_record(record: dict[str, Any]) -> bool:
    if record.get("ssrf_channel") == "oob":
        return False
    if record.get("ssrf_channel") == "inband":
        return True
    # Legacy JSON without channel: treat SSRF module rows as in-band.
    return record.get("module") == SSRF_MODULE_REPORT_NAME


def grouping_attack_class(record: dict[str, Any]) -> str:
    """Logical attack class for dedupe keys (in-band SSRF collapses to one bucket)."""
    if _is_inband_ssrf_record(record):
        return _SSRF_INTERNAL_CLASS
    attack = record.get("attack_info") or {}
    raw_type = str(attack.get("type") or "")
    return canonical_attack_type_for_grouping(raw_type)


def presentation_for_vulnerability_record(record: dict[str, Any]) -> dict[str, Any]:
    """Apply display labels after dedupe (e.g. in-band SSRF -> SSRF-Internal)."""
    out = copy.deepcopy(record)
    if not _is_inband_ssrf_record(out):
        return out
    attack = out.setdefault("attack_info", {})
    original = str(attack.get("type") or "")
    attack["type"] = _SSRF_INTERNAL_CLASS
    if original and original != _SSRF_INTERNAL_CLASS:
        attack["ssrf_variant"] = original
    return out


def vulnerability_group_key(record: dict[str, Any]) -> tuple[str, str, str, str, str]:
    """
    Group by URL, HTTP method, parameter placement, parameter name, and attack class.

    In-band SSRF rows share one class (``SSRF-Internal``). Other types use
    ``attack_info.type`` with mutation suffixes stripped.
    """
    target = record.get("target") or {}
    return (
        str(target.get("url") or ""),
        str(target.get("method") or ""),
        str(target.get("location") or ""),
        str(target.get("parameter") or ""),
        grouping_attack_class(record),
    )


def vulnerability_sort_key(record: dict[str, Any]) -> tuple[int, str, str]:
    attack = record.get("attack_info") or {}
    target = record.get("target") or {}
    return (
        severity_rank(str(attack.get("severity") or "high")),
        str(target.get("url") or ""),
        str(target.get("parameter") or ""),
    )


def dedupe_vulnerabilities(
    records: list[dict[str, Any]],
    *,
    mode: Literal["first_in_order", "best_evidence"] = "first_in_order",
) -> list[dict[str, Any]]:
    """
    Collapse records that share the same group key to a single entry (one PoC).

    - first_in_order: keep the first record per key (scan / discovery order).
    - best_evidence: for each key, pick the lowest severity rank, then shortest
      payload string, then earliest index in the input list (for offline JSON).
    """
    if mode == "first_in_order":
        seen: set[tuple[str, str, str, str, str]] = set()
        out: list[dict[str, Any]] = []
        for rec in records:
            key = vulnerability_group_key(rec)
            if key in seen:
                continue
            seen.add(key)
            out.append(presentation_for_vulnerability_record(rec))
        return out

    buckets: dict[tuple[str, str, str, str, str], list[tuple[int, dict[str, Any]]]] = (
        defaultdict(list)
    )
    for index, rec in enumerate(records):
        buckets[vulnerability_group_key(rec)].append((index, rec))

    picked: list[dict[str, Any]] = []
    for _key, items in sorted(buckets.items(), key=lambda kv: kv[0]):
        def score(item: tuple[int, dict[str, Any]]) -> tuple[int, int, int]:
            idx, rec = item
            attack = rec.get("attack_info") or {}
            payload = str(attack.get("payload_value") or "")
            return (severity_rank(str(attack.get("severity") or "high")), len(payload), idx)

        picked.append(min(items, key=score)[1])
    return [presentation_for_vulnerability_record(r) for r in picked]


def dedupe_report_document(
    report: dict[str, Any],
    *,
    mode: Literal["first_in_order", "best_evidence"] = "best_evidence",
) -> dict[str, Any]:
    """Return a deep-copied report with vulnerabilities deduped and summary updated."""
    data = copy.deepcopy(report)
    vulns = list(data.get("vulnerabilities") or [])
    raw_count = len(vulns)
    deduped = dedupe_vulnerabilities(vulns, mode=mode)
    deduped_sorted = sorted(deduped, key=vulnerability_sort_key)
    data["vulnerabilities"] = deduped_sorted
    meta = data.setdefault("metadata", {})
    summary = meta.setdefault("summary", {})
    summary["findings"] = len(deduped_sorted)
    summary["findings_raw"] = raw_count
    return data


def full_report_path(output_path: str | Path) -> Path:
    """scan_report.json -> scan_report_full.json"""
    p = Path(output_path)
    return p.with_name(f"{p.stem}_full{p.suffix}")
