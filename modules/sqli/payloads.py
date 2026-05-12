import os
import random
import dataclasses
from core.models import Payload

def _resolve_payload_file() -> str | None:
    candidates = [
        os.path.join("config", "payloads", "sqli", "sqli.txt"),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return None

def get_dbms_specific_marker(text: str, dbms: str) -> str:
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
        return " + ".join([f"'{c}'" for c in text])

def get_sqli_payloads() -> list[Payload]:
    payloads = []
    file_path = _resolve_payload_file()
    if not file_path:
        return []

    DELIM_START = "SVSDAAAA"
    DELIM_STOP = "VASDAAAA"
    marker_cache = {}

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":::" not in line:
                continue

            parts = [p.strip() for p in line.split(":::", 3)]

            if len(parts) >= 4:
                raw_value = parts[0]
                attack_type = parts[1]
                risk_level = parts[2]
                dbms = parts[3]

                if dbms not in marker_cache:
                    marker_cache[dbms] = (
                        get_dbms_specific_marker(DELIM_START, dbms),
                        get_dbms_specific_marker(DELIM_STOP, dbms),
                        get_dbms_specific_marker("vun", dbms)
                    )
                
                start_marker, stop_marker, vun_marker = marker_cache[dbms]

                # 1. 플레이스홀더 및 마커 치환
                final_value = raw_value
                final_value = final_value.replace("'[START_M]'", start_marker).replace("[START_M]", start_marker)
                final_value = final_value.replace("'[STOP_M]'", stop_marker).replace("[STOP_M]", stop_marker)
                final_value = final_value.replace("'vun'", vun_marker).replace('"vun"', vun_marker)

                # 2. 숫자형 및 기타 플레이스홀더 최종 처리
                for i in range(1, 10):
                    final_value = final_value.replace(f"[RANDNUM{i}]", str(i))
                final_value = final_value.replace("[RANDNUM]", "1")
                final_value = final_value.replace("[ORIGVALUE]", "1")
                final_value = final_value.replace("[SLEEPTIME]", "5")

                payloads.append(Payload(
                    value=final_value,
                    attack_type=attack_type,
                    risk_level=risk_level
                ))
                
    return payloads