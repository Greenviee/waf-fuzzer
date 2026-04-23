import re

def detect_sqli(response, payload, elapsed_time, exploit_signatures, syntax_signatures, original_res=None):
    evidences = []
    res_text = response.text
    attack_type = payload.attack_type.lower()
    
    # [1] 단순 문법 오류(Syntax Error) 여부 확인
    has_syntax_error = False
    for pattern in syntax_signatures:
        if re.search(pattern, res_text, re.IGNORECASE | re.DOTALL):
            has_syntax_error = True
            break

    # [2] 오탐 방지용 정밀 세정 (Precision Scrubbing)
    scrubbed_text = res_text
    syntax_error_echo_patterns = [
        r"(near\s+)'(.*?)'(\s+at\s+line)",       # MySQL
        r"(syntax\s+error\s+near\s+)'(.*?)'()",  # MSSQL
        r"(at\s+line\s+\d+:\s+)(.*?)()"           # PostgreSQL
    ]
    
    for p in syntax_error_echo_patterns:
        # 문법 에러가 반사한 페이로드 조각만 [SYNTAX_ECHO]로 바꿈
        scrubbed_text = re.sub(p, r"\1'[SYNTAX_ECHO]'\3", scrubbed_text, flags=re.I | re.DOTALL)

    # 1. 시간 기반 탐지
    if "time_blind" in attack_type or "stacked" in attack_type:
        if elapsed_time >= 4.5:
            evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")

    # 2. 에러 기반 탐지 (구분자 검증)
    if "error_based" in attack_type:
        if "SVSDAAAAvunVASDAAAA".lower() in scrubbed_text.lower():
            evidences.append("[Error] SQLi execution marker 'SNDNvunDNSN' found (confirmed execution)")
        
        # 추가로 Exploit 시그니처 매칭 (Scrubbed text에서)
        for pattern in exploit_signatures:
            if re.search(pattern, scrubbed_text, re.IGNORECASE | re.DOTALL):
                evidences.append(f"[Error] Exploit signature matched: {pattern}")
                break

    # 3. 데이터 반사 탐지 (Union / Inline)
    if "union" in attack_type or "inline" in attack_type:
        # 에러가 없는 상태에서 마커가 발견되어야 실제 데이터 추출 성공
        if "SVvunV".lower() in scrubbed_text.lower() and not has_syntax_error:
            evidences.append(f"[Reflection] Value 'SVvunV' reflected without syntax error")

    # 4. 불리언 기반 탐지
    if "boolean_blind" in attack_type and original_res:
        if not has_syntax_error:
            original_len = len(original_res.text)
            current_len = len(res_text)
            if original_len > 0:
                diff_ratio = abs(original_len - current_len) / original_len
                if diff_ratio > 0.1:
                    evidences.append(f"[Boolean] Logic change detected ({diff_ratio:.1%})")

    return len(evidences) > 0, evidences