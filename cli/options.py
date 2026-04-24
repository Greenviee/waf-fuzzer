from __future__ import annotations


def parse_cookies(raw: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for item in raw.split(";"):
        item = item.strip()
        if not item or "=" not in item:
            continue
        name, value = item.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


def parse_bf_length(raw: str, fallback_max: int) -> tuple[int, int]:
    """
    Parse brute-force length expression.
    Supported formats:
      - "8"   -> (1, 8)
      - "2~8" -> (2, 8)
    """
    text = (raw or "").strip()
    if not text:
        return 1, fallback_max

    if "~" in text:
        left, right = text.split("~", 1)
        min_len = int(left.strip())
        max_len = int(right.strip())
    else:
        min_len = 1
        max_len = int(text)

    if min_len < 1 or max_len < 1 or min_len > max_len:
        raise ValueError(f"Invalid --bf-length value: {raw!r}")
    return min_len, max_len

