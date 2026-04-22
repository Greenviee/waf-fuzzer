import os
from core.models import Payload


def _resolve_payload_file() -> str | None:
    candidates = [
        os.path.join("config", "payloads", "sqli_final.txt"),
        os.path.join("config", "payloads", "sqli.txt"),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return None


def get_sqli_payloads() -> list[Payload]:
    payloads = []
    file_path = _resolve_payload_file()
    if not file_path:
        return []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "||" not in line:
                continue
            
            # 1. 파싱: 값 || 타입 || 위험도
            parts = line.split("||")
            if len(parts) == 3:
                raw_value = parts[0].strip()
                attack_type = parts[1].strip()
                risk_level = parts[2].strip()

                # 2. 미처 치환되지 않은 플레이스홀더 최종 처리
                # SQLmap 데이터에 남아있는 [RANDNUM1], [RANDNUM2] 등을 실제 숫자로 변경
                final_value = raw_value
                for i in range(1, 10):
                    final_value = final_value.replace(f"[RANDNUM{i}]", str(i))
                
                # 혹시 남아있을 수 있는 기타 마커들 처리
                final_value = final_value.replace("[RANDNUM]", "1")
                final_value = final_value.replace("[ORIGVALUE]", "1")

                # 3. Payload 객체 생성 및 리스트 추가
                payloads.append(Payload(
                    value=final_value,
                    attack_type=attack_type,
                    risk_level=risk_level
                ))
                
    return payloads