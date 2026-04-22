import re

def detect_sqli(response, payload, elapsed_time, error_signatures, original_res=None):
    """
    HTTP 응답을 분석하여 SQL Injection 징후를 탐지합니다.
    
    Args:
        response: 공격 후 받은 HTTP 응답 객체
        payload: 사용된 Payload 객체
        elapsed_time: 응답 소요 시간
        error_signatures: SQLiModule에서 전달해준 에러 정규식 리스트
        original_res: 공격 전의 정상 응답 객체 (선택)
        
    Returns:
        tuple: (is_vulnerable: bool, evidences: list)
    """
    evidences = []
    res_text = response.text
    attack_type = payload.attack_type.lower()

    # 1. 시간 기반 탐지 (Time-based Blind / Stacked)
    if "time_blind" in attack_type or "stacked" in attack_type:
        if elapsed_time >= 4.5:
            evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")

    # 2. 에러 기반 탐지 (Error-based)
    # 모든 응답에 대해 모듈에서 로드한 시그니처와 매칭 수행
    for pattern in error_signatures:
        try:
            if re.search(pattern, res_text, re.IGNORECASE | re.DOTALL):
                evidences.append(f"[Error] SQL signature matched: {pattern}")
                break
        except re.error:
            continue

    # 3. 데이터 반사 탐지 (Union / Inline Query)
    if "union" in attack_type or "inline" in attack_type:
        target_str = "vun" # 전처리 시 치환한 상수 값
        if target_str in res_text:
            evidences.append(f"[Reflection] Injected value '{target_str}' found in response")

    # 4. 불리언 기반 탐지 (Boolean-based Blind)
    if "boolean_blind" in attack_type and original_res:
        original_len = len(original_res.text)
        current_len = len(res_text)
        
        if original_len > 0:
            diff_ratio = abs(original_len - current_len) / original_len
            if diff_ratio > 0.1: # 10% 이상의 길이 변화 시 징후로 판단
                evidences.append(f"[Boolean] Length changed: {original_len} -> {current_len} ({diff_ratio:.1%})")

    is_vulnerable = len(evidences) > 0
    return is_vulnerable, evidences