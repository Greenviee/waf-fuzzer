import os
from core.models import Payload

def get_xss_payloads() -> list[Payload]:
    payloads = []
    file_path = os.path.join("config", "payloads", "xss.txt")
    
    if not os.path.exists(file_path):
        return []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "||" not in line:
                continue
            
            parts = line.split("||")
            if len(parts) == 3:
                payloads.append(Payload(
                    value=parts[0].strip(),
                    attack_type=parts[1].strip(),
                    risk_level=parts[2].strip()
                ))
    return payloads