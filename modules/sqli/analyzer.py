def analyze(self, response, payload, elapsed_time, original_res=None):
    """
    SQLmap에서 추출한 태그를 기반으로 한 다중 기법 분석기
    """
    res_text = response.text
    res_text_lower = res_text.lower()

    # 1. 시간 기반 탐지 (Time-based / Stacked)
    # 가장 확실한 지표: 서버가 명령에 의해 의도적으로 응답을 늦췄는가?
    if payload.attack_type in ["SQLi-Time", "SQLi-Stacked"]:
        if elapsed_time >= 4.5:
            return True, f"Time delay detected: {elapsed_time:.2f}s"

    # 2. 에러 기반 탐지 (Error-based)
    # DB가 내뱉는 문법 에러가 포함되어 있는가?
    if payload.attack_type == "SQLi-Error":
        for sig in self.error_signatures:
            if sig in res_text_lower:
                return True, f"SQL Error signature found: {sig}"

    # 3. 유니온 기반 탐지 (Union Query)
    # 핵심: [RANDSTR]로 주입한 'vun'이 화면에 출력되었는가?
    if payload.attack_type == "SQLi-Union":
        # 추출 스크립트에서 [RANDSTR] -> 'vun'으로 치환했으므로 이를 검사
        target_str = "vun"
        if target_str in res_text:
            return True, f"Union-based: Injected string '{target_str}' found in response"

    # 4. 인라인 쿼리 탐지 (Inline Query)
    # 특징: 서브쿼리 결과값이 기존 데이터 자리에 반사됨
    if payload.attack_type == "SQLi-Inline":
        target_str = "vun"
        # Inline 쿼리 결과로 'vun'이 출력되거나, 에러를 유도함
        if target_str in res_text:
            return True, f"Inline-based: Subquery result '{target_str}' reflected"
        # Inline 방식도 에러를 유도할 수 있으므로 에러 체크 병행
        for sig in self.error_signatures:
            if sig in res_text_lower:
                return True, f"Inline-based: Error signature found: {sig}"

    # 5. 불리언 기반 탐지 (Boolean-based)
    # 특징: 에러도 안 뜨고 값도 안 보이지만, '참'과 '거짓'일 때 페이지 내용(길이)이 다름
    if payload.attack_type == "SQLi-Boolean" and original_res:
        # 정상 응답(original_res)의 길이와 현재 응답의 길이 차이 계산
        original_len = len(original_res.text)
        current_len = len(res_text)
        
        if original_len > 0:
            diff_ratio = abs(original_len - current_len) / original_len
            # 보통 10% 이상 차이가 나면 리스트가 사라졌거나 결과가 바뀐 것으로 간주
            if diff_ratio > 0.1:
                return True, f"Boolean-based: Response length changed by {diff_ratio:.1%}"

    return False, ""