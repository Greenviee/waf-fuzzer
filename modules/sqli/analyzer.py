import re
import html
from urllib.parse import unquote

def detect_sqli(response, payload, elapsed_time, exploit_signatures, syntax_signatures, original_res=None):
    """
    HTTP 응답을 분석하여 SQL Injection 징후를 탐지합니다.
    Greedy Regex Scrubbing을 통해 문법 에러 메시지 내부의 페이로드 반사를 제거합니다.
    """
    evidences = []
    res_text = response.text
    attack_type = payload.attack_type.lower()
    
    marker = "SVSDAAAAvunVASDAAAA"
    
    # [1] 단순 문법 오류(Syntax Error) 여부 확인
    has_syntax_error = False
    for pattern in syntax_signatures:
        if re.search(pattern, res_text, re.IGNORECASE | re.DOTALL):
            has_syntax_error = True
            break

    # [2] 오탐 방지용 정밀 세정 (Precision Scrubbing)
    # (.*?) -> (.+) 로 변경하여 마지막 따옴표까지 greedy 매칭
    scrubbed_text = res_text
    syntax_error_echo_patterns = [
        r"(near\s+)'(.+)'(\s+at\s+line)",       # MySQL / MariaDB 
        r"(syntax\s+error\s+near\s+)'(.+)'()",  # MSSQL / SQLite 
        r"(at\s+line\s+\d+:\s+)(.+)()"           # PostgreSQL
    ]
    
    for p in syntax_error_echo_patterns:
        try:
            scrubbed_text = re.sub(p, r"\1'[SYNTAX_ECHO]'\3", scrubbed_text, flags=re.I | re.DOTALL)
        except Exception:
            continue

    # 페이로드 원본/인코딩본이 본문에 직접 반사된 경우 제거
    payload_variants = [payload.value, unquote(payload.value), html.escape(payload.value)]
    for var in filter(None, set(payload_variants)):
        scrubbed_text = scrubbed_text.replace(var, "[DIRECT_REFLECTION]")


    # 1. 시간 기반 탐지
    if "time_blind" in attack_type or "stacked" in attack_type:
        if elapsed_time >= 4.5:
            evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")

    # 2. 에러 기반 탐지 (구분자 검증)
    if "error_based" in attack_type:
        # 에러 메시지 에코 영역([SYNTAX_ECHO])을 지웠는데도 마커가 남아있는가?
        if marker.lower() in scrubbed_text.lower():
            evidences.append(f"[Error] SQLi execution marker '{marker}' confirmed in DB output")
        
        # 실제 Exploit 시그니처 매칭 (Scrubbed text에서 검색하여 문법 에러와 분리)
        for pattern in exploit_signatures:
            if re.search(pattern, scrubbed_text, re.IGNORECASE | re.DOTALL):
                evidences.append(f"[Error] Exploit signature matched: {pattern}")
                break

    # 3. 데이터 반사 탐지 (Union / Inline Query)
    if "union" in attack_type or "inline" in attack_type:
        # 문법 에러가 '없어야' 하며, 세정된 텍스트에 마커가 살아있어야 실제 데이터로 간주
        if not has_syntax_error and marker.lower() in scrubbed_text.lower():
            evidences.append(f"[Reflection] Injected value found as legitimate content")

    # 4. 불리언 기반 탐지
    if "boolean_blind" in attack_type and original_res:
        # 문법 에러가 발생했다면 응답 길이 변화는 논리가 아닌 에러 페이지 때문이므로 무시
        if not has_syntax_error:
            original_len = len(original_res.text)
            current_len = len(res_text)
            if original_len > 0:
                diff_ratio = abs(original_len - current_len) / original_len
                # 10% 이상 차이가 나고 문법 에러가 없을 때만 성공으로 판단
                if diff_ratio > 0.1:
                    evidences.append(f"[Boolean] Logical change detected ({diff_ratio:.1%})")

    is_vulnerable = len(evidences) > 0
    return is_vulnerable, evidences