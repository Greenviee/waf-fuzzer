def analyze(self, response, payload, elapsed_time, original_res=None):
    """
    발견된 모든 취약점 징후를 수집하여 반환합니다.
    """
    evidences = []  # 발견된 증거들을 담을 리스트
    res_text = response.text
    res_text_lower = res_text.lower()

    # 1. 시간 기반 탐지 (Time-based / Stacked)
    if payload.attack_type in ["SQLi-Time", "SQLi-Stacked"]:
        if elapsed_time >= 4.5:
            evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")

    # 2. 에러 기반 탐지 (Error-based)
    # 특정 타입이 아니더라도 모든 응답에서 에러가 발생하는지 상시 체크 (더 안전함)
    for sig in self.error_signatures:
        if sig in res_text_lower:
            evidences.append(f"[Error] SQL signature found: {sig}")
            break # 에러 시그니처는 하나만 발견해도 충분하므로 한 루프 내에서 break

    # 3. 유니온 및 인라인 기반 탐지 (String Reflection)
    if payload.attack_type in ["SQLi-Union", "SQLi-Inline"]:
        target_str = "vun" # 추출 시 설정한 RANDSTR 값
        if target_str in res_text:
            evidences.append(f"[Reflection] Injected value '{target_str}' found in response")

    # 4. 불리언 기반 탐지 (Boolean-based)
    if payload.attack_type == "SQLi-Boolean" and original_res:
        original_len = len(original_res.text)
        current_len = len(res_text)
        
        if original_len > 0:
            diff_ratio = abs(original_len - current_len) / original_len
            if diff_ratio > 0.1:
                evidences.append(f"[Boolean] Length changed: {original_len} -> {current_len} ({diff_ratio:.1%})")

    # 최종 결과 반환
    # evidences 리스트가 비어있지 않으면 취약한 것으로 간주 (True)
    is_vulnerable = len(evidences) > 0
    return is_vulnerable, evidences