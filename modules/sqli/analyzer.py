import re
import html
from urllib.parse import unquote

def detect_sqli(response, payload, elapsed_time, exploit_signatures, syntax_signatures, original_res=None):

    evidences = []
    res_text = response.text
    attack_type = payload.attack_type.lower()
    payload_value = payload.value
    marker = "SVSDAAAAvunVASDAAAA"

    # [1] 단순 문법 오류(Syntax Error) 식별 및 영역 제거
    has_syntax_error = False
    scrubbed_text = res_text
    
    # 문법 에러 메시지 영역 전체를 지워 '단순 반사'된 마커를 제거
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

    # 1. 시간 기반 탐지 (Time-based Detection)
    timing_keywords = ["sleep(", "waitfor delay", "pg_sleep", "benchmark(", "dbms_pipe.receive_message"]
    has_timing_intent = any(k in payload_value.lower() for k in timing_keywords)
    
    # "time" 태그가 있거나, "stacked" 태그가 있거나, 페이로드 자체에 sleep 등 키워드가 있는 경우
    is_time_related = "time" in attack_type or "stacked" in attack_type or has_timing_intent

    if is_time_related:
        if elapsed_time >= 4.5:
            evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")

    # 2. 실행/런타임 에러 시그니처 매칭 (Exploit & Runtime)
    for pattern in exploit_signatures:
        if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
            evidences.append(f"[Error] SQL Execution Error matched: {pattern}")
            break

    # 3. 마커 검증 및 분류
    if marker.lower() in scrubbed_text.lower():
        if has_syntax_error:
            # 에러 메시지가 있는 상태에서 마커가 발견됨 -> 에러 출력 기반 성공
            evidences.append(f"[Error] SQLi execution marker '{marker}' confirmed in DB output")
        else:
            # 에러 메시지 없이 깨끗한 본문에서 마커가 발견됨 -> Union/Inline 기반 성공
            evidences.append(f"[Reflection] SQLi marker '{marker}' found in legitimate content")

    # 4. 불리언 기반 탐지
    if not is_time_related and not evidences and not has_syntax_error and original_res:
        # A. HTTP 상태 코드 변화 확인
        if response.status_code != original_res.status_code:
            evidences.append(f"[Boolean] Status Code changed: {original_res.status_code} -> {response.status_code}")
        
        # B. 본문 길이 변화 분석
        original_len = len(original_res.text)
        current_len = len(res_text)
        
        if original_len > 0:
            diff_ratio = abs(original_len - current_len) / original_len
            diff_bytes = abs(original_len - current_len)
            
            # 10% 이상 차이나고, 실제 차이가 20바이트 이상일 때
            if diff_ratio > 0.1 and diff_bytes > 20:
                evidences.append(f"[Boolean] Content length changed by {diff_ratio:.1%} ({diff_bytes} bytes)")
            
            # C. 특정 키워드 소멸/생성 확인 (간단한 Heuristic)
            critical_keywords = ["first name", "surname", "id:", "admin", "login", "welcome"]
            for kw in critical_keywords:
                if (kw in scrubbed_text.lower()) and (kw not in res_text.lower()):
                    evidences.append(f"[Boolean] Critical keyword '{kw}' disappeared from response")
                    break

    is_vulnerable = len(evidences) > 0
    return is_vulnerable, evidences