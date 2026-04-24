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

    # 1. 시간 기반 탐지
    if "time" in attack_type or "stacked" in attack_type:
        if elapsed_time >= 4.5:
            evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")
            print("time")

    # 2. 실행/런타임 에러 시그니처 매칭 (Exploit & Runtime)
    for pattern in exploit_signatures:
        if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
            evidences.append(f"[Error] SQL Execution Error matched: {pattern}")
            print("runtime/function")
            break

    # 3. 마커 검증 및 분류
    if marker.lower() in scrubbed_text.lower():
        if has_syntax_error:
            # 에러 메시지가 있는 상태에서 마커가 발견됨 -> 에러 출력 기반 성공
            evidences.append(f"[Error] SQLi execution marker '{marker}' confirmed in DB output")
            print("marker in error")
        else:
            # 에러 메시지 없이 깨끗한 본문에서 마커가 발견됨 -> Union/Inline 기반 성공
            evidences.append(f"[Reflection] SQLi marker '{marker}' found in legitimate content")
            print("marker w/o error")

    # 4. 불리언 기반 탐지
    if not has_syntax_error:
        original_len = len(original_res.text)
        current_len = len(res_text)
        if original_len > 0:
            diff_ratio = abs(original_len - current_len) / original_len
            if diff_ratio > 0.1:
                evidences.append(f"[Boolean] Logical change detected ({diff_ratio:.1%})")
                print("boolean")

    is_vulnerable = len(evidences) > 0
    return is_vulnerable, evidences