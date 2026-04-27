import os
import random
from core.models import Payload

def _resolve_payload_file() -> str | None:
    candidates = [
        os.path.join("config", "payloads", "sqli.txt"),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return None

def get_dbms_specific_marker(text: str, dbms: str) -> str:
    """
    DBMS별로 최적의 문자열 생성 방식을 선택하여 
    엔진의 직접 반사 제거(scrubbed_text) 로직을 우회함.
    """
    if not text:
        return "''"
    
    # 1. Hex 리터럴 지원 (MySQL, MSSQL, Spanner 등)
    if dbms in ["MySQL", "Microsoft SQL Server", "Spanner"]:
        return f"0x{text.encode().hex()}"
    
    # 2. SQLite 전용 Hex 방식
    elif dbms == "SQLite":
        return f"x'{text.encode().hex()}'"

    # 3. CHR 함수 결합 방식 (Oracle, PostgreSQL)
    elif dbms in ["Oracle", "PostgreSQL"]:
        chars = [f"CHR({ord(c)})" for c in text]
        return "||".join(chars)
    
    # 4. MS Access 결합 방식
    elif dbms == "MS Access":
        chars = [f"CHR({ord(c)})" for c in text]
        return "&".join(chars)

    # 5. 기타/Generic: 문자열 쪼개기 시도
    else:
        # 'v' + 'un' 형태로 쪼개서 반사 제거 우회
        return " + ".join([f"'{c}'" for c in text])

def get_sqli_payloads() -> list[Payload]:
    payloads = []
    file_path = _resolve_payload_file()
    if not file_path:
        return []

    # 고정형 구분자 정의
    DELIM_START = "SVSDAAAA"
    DELIM_STOP = "VASDAAAA"

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # ::: 구분자로 파싱 (Payload ::: Type ::: Risk ::: DBMS)
            if not line or ":::" not in line:
                continue
            
            parts = line.split("::: ")
            if len(parts) >= 4:
                raw_value = parts[0].strip()
                attack_type = parts[1].strip()
                risk_level = parts[2].strip()
                dbms = parts[3].strip()

                # DBMS별 우회용 마커 생성
                start_marker = get_dbms_specific_marker(DELIM_START, dbms)
                stop_marker = get_dbms_specific_marker(DELIM_STOP, dbms)
                vun_marker = get_dbms_specific_marker("vun", dbms)

                # 1. 플레이스홀더 및 마커 치환
                final_value = raw_value
                
                # [START_M], [STOP_M] 치환 시 따옴표가 포함된 '[START_M]' 형식을 먼저 치환하여 쿼리 문법 오류 방지
                final_value = final_value.replace("'[START_M]'", start_marker).replace("[START_M]", start_marker)
                final_value = final_value.replace("'[STOP_M]'", stop_marker).replace("[STOP_M]", stop_marker)
                
                # 고정 마커 'vun' 치환
                final_value = final_value.replace("'vun'", vun_marker).replace('"vun"', vun_marker)

                # 2. 기타 플레이스홀더 처리
                for i in range(1, 10):
                    final_value = final_value.replace(f"[RANDNUM{i}]", str(i))
                final_value = final_value.replace("[RANDNUM]", "1")
                final_value = final_value.replace("[ORIGVALUE]", "1")
                final_value = final_value.replace("[SLEEPTIME]", "5")

                # Payload 객체 생성
                payloads.append(Payload(
                    value=final_value,
                    attack_type=attack_type,
                    risk_level=risk_level
                ))
                
    return payloads