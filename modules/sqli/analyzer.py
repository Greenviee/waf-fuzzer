import re
import html
from urllib.parse import unquote

def detect_sqli(response, payload, elapsed_time, exploit_signatures, syntax_signatures, original_res=None, requester=None):
    evidences = []
    res_text = response.text
    current_status = getattr(response, "status", getattr(response, "status_code", None))
    orig_status = getattr(original_res, "status", getattr(original_res, "status_code", None)) if original_res else None

    attack_type = payload.attack_type.lower()
    payload_value = payload.value
    marker = "SVSDAAAAvunVASDAAAA"

    # [1] 단순 문법 오류(Syntax Error) 식별 및 영역 제거
    has_syntax_error = False
    scrubbed_text = res_text
    
    syntax_error_full_patterns = [
        r"you have an error in your sql syntax;.*?near\s+'.+?'\s+at\s+line\s+\d+", 
        r"microsoft\s+ole\s+db\s+provider\s+for\s+sql\s+server.*?'(.+?)'",         
        r"postgresql\s+query\s+failed:.*?at\s+or\s+near\s+\".+?\"",               
        r"syntax\s+error\s+near\s+'.+?'",
    ]

    for p in syntax_error_full_patterns:
        if re.search(p, scrubbed_text, re.I | re.DOTALL):
            has_syntax_error = True
            scrubbed_text = re.sub(p, "[FULL_SYNTAX_ERROR_REMOVED]", scrubbed_text, flags=re.I | re.DOTALL)

    if not has_syntax_error:
        for pattern in syntax_signatures:
            if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
                has_syntax_error = True
                break

    # [2] 직접 반사 제거
    payload_variants = [payload_value, unquote(payload_value), html.escape(payload_value)]
    for var in filter(None, set(payload_variants)):
        scrubbed_text = scrubbed_text.replace(var, "[DIRECT_REFLECTION_REMOVED]")

    # --- 탐지 로직 시작 ---

    # 1. 시간 기반 탐지
    timing_keywords = ["sleep(", "waitfor delay", "pg_sleep", "benchmark(", "dbms_pipe.receive_message"]
    has_timing_intent = any(k in payload_value.lower() for k in timing_keywords)
    is_time_related = "time" in attack_type or "stacked" in attack_type or has_timing_intent

    if is_time_related and elapsed_time >= 4.5:
        evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")

    # 2. 실행/런타임 에러 시그니처 매칭 및 DBMS 불일치 판별
    # DBMS 불일치를 나타내는 패턴들
    mismatch_patterns = [
        r"FUNCTION\s+.*?\s+does\s+not\s+exist",
        r"invalid\s+identifier",
        r"table\s+or\s+view\s+does\s+not\s+exist",
        r"Could\s+not\s+find\s+stored\s+procedure",
        r"Invalid\s+object\s+name",
        r"no\s+such\s+function"
    ]

    has_execution_error = False
    for pattern in exploit_signatures:
        if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
            # 매칭된 에러가 DBMS 불일치인지 확인
            is_mismatch = any(re.search(mp, scrubbed_text, re.I) for mp in mismatch_patterns)
            
            if is_mismatch:
                evidences.append(f"[Potential] DBMS Mismatch Error: {pattern}")
            else:
                evidences.append(f"[Error] SQL Execution Error: {pattern}")
                has_execution_error = True # 실제 익스플로잇 성공 에러로 간주
            break

    # 3. 마커 검증 (가장 확실한 성공 지표)
    marker_lower = marker.lower()
    if marker_lower in res_text.lower() and marker_lower in scrubbed_text.lower():
        if has_syntax_error or has_execution_error:
            evidences.append(f"[Error] SQLi execution marker '{marker}' confirmed in DB output")
        else:
            evidences.append(f"[Reflection] SQLi marker found in legitimate content")

    # 4. 불리언 기반 탐지
    if not evidences and not has_syntax_error and original_res:
        orig_text_lower = original_res.text.lower()
        curr_text_lower = scrubbed_text.lower()

        if len(orig_text_lower) > 0:
            diff_bytes = abs(len(original_res.text) - len(res_text))
            
            if diff_bytes > 0:
                evidences.append(f"[Boolean] Content length changed by {diff_bytes} bytes")
            
            # exists, missing 등이 토글되었는지 확인
            blind_keywords = ["exists", "missing", "found", "success", "failed", "invalid", "true", "false"]
            for kw in blind_keywords:
                # 원본 존재 여부와 현재 존재 여부가 다르면
                if (kw in orig_text_lower) != (kw in curr_text_lower):
                    evidences.append(f"[Boolean] Blind keyword '{kw}' state inverted")
                    break

    is_vulnerable = len(evidences) > 0
    return is_vulnerable, evidences