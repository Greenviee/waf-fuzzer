import re

def detect_sqli(response, payload, elapsed_time, exploit_signatures, syntax_signatures, original_res=None):
    """
    HTTP 응답을 분석하여 SQL Injection 징후를 탐지합니다.
    단순 문법 에러와 실제 공격 성공을 구분합니다.
    """
    evidences = []
    res_text = response.text
    res_text_lower = res_text.lower()
    attack_type = payload.attack_type.lower()

    # 응답에 단순 문법 오류(Syntax Error)가 포함되어 있는지 확인
    has_syntax_error = False
    for pattern in syntax_signatures:
        try:
            if re.search(pattern, res_text, re.IGNORECASE | re.DOTALL):
                has_syntax_error = True
                break
        except re.error: continue

    # 1. 시간 기반 탐지 (Body 내용과 상관없으므로 유지)
    if "time_blind" in attack_type or "stacked" in attack_type:
        if elapsed_time >= 4.5:
            evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")

    # 2. 에러 기반 탐지
    if "error_based" in attack_type:
        # 2-1. 실제 DB 정보가 유출되는 'Exploit 시그니처' 매칭
        for pattern in exploit_signatures:
            try:
                if re.search(pattern, res_text, re.IGNORECASE | re.DOTALL):
                    evidences.append(f"[Error] Valid Exploit matched: {pattern}")
                    break
            except re.error: continue
        
        # 2-2. 마커 'vun'이 에러 메시지에 포함되어 출력되는가? (성공 확률 매우 높음)
        # 예: XPATH syntax error: ':vun'
        if "vun" in res_text and has_syntax_error:
            evidences.append("[Error] Injected marker 'vun' reflected in SQL error message")

    # 3. 데이터 반사 탐지 (Union / Inline Query)
    if "union" in attack_type or "inline" in attack_type:
        # 문법 에러가 없는 상태에서 'vun'이 보일 때만 유효한 데이터로 간주
        if "vun" in res_text and not has_syntax_error:
            evidences.append(f"[Reflection] Injected value 'vun' found in response")

    # 4. 불리언 기반 탐지 (Boolean-based Blind)
    if "boolean_blind" in attack_type and original_res:
        # 문법 에러 때문에 페이지 길이가 변한 것이 아닐 때만 비교 로직 수행
        if not has_syntax_error:
            original_len = len(original_res.text)
            current_len = len(res_text)
            
            if original_len > 0:
                diff_ratio = abs(original_len - current_len) / original_len
                # 10% 이상 차이가 나고, 문법 에러가 없다면 논리적 변화로 판단
                if diff_ratio > 0.1:
                    evidences.append(f"[Boolean] Logical change detected ({diff_ratio:.1%})")

    # 최종 취약점 판별: 
    # 문법 에러(has_syntax_error)가 있더라도 'vun'이 박혀있거나 
    # exploit 시그니처가 매칭되는 등의 확실한 근거가 evidences에 담겨야만 True 반환
    is_vulnerable = len(evidences) > 0
    return is_vulnerable, evidences