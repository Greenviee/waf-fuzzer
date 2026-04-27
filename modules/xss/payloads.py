import os
from core.models import Payload

def _resolve_payload_file() -> str | None:
    candidates = [
        os.path.join("config", "payloads", "xss_final.txt"),
        os.path.join("config", "payloads", "xss.txt"),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return None

def get_xss_payloads() -> list[Payload]:
    payloads = []
    file_path = _resolve_payload_file()
    if not file_path:
        return []

    # XSS 탐지용 고유 구분자
    DELIM_START = "XSSDAAAA"
    DELIM_STOP = "XSSSAAAA"

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "||" not in line:
                continue
            
            parts = line.rsplit("||", 2)
            if len(parts) == 3:
                raw_value = parts[0].strip()
                attack_type = parts[1].strip()
                risk_level = parts[2].strip()

                # 1. 마커(vun) 주위에 고유 구분자 주입
                final_value = raw_value.replace("vun", f"{DELIM_START}vun{DELIM_STOP}")
                
                # 2. 플레이스홀더 치환 (랜덤값 등)
                for i in range(1, 10):
                    final_value = final_value.replace(f"[RANDNUM{i}]", str(i))
                final_value = final_value.replace("[RANDNUM]", "123")
                final_value = final_value.replace("[ORIGVALUE]", "test")

                payloads.append(Payload(
                    value=final_value,
                    attack_type=attack_type,
                    risk_level=risk_level
                ))
                
    return payloads