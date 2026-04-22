import os
from core.models import Payload

def get_sqli_payloads() -> list[Payload]:
    payloads = []
    # 프로젝트 루트 기준 경로 설정
    file_path = os.path.join("config", "payloads", "sqli.txt")
    
    if not os.path.exists(file_path):
        return []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "||" not in line:
                continue
            
            # 값 || 타입 || 위험도 파싱
            parts = line.split("||")
            if len(parts) == 3:
                payloads.append(Payload(
                    value=parts[0].strip(),
                    attack_type=parts[1].strip(),
                    risk_level=parts[2].strip()
                ))
    return payloads