import re
import html
from urllib.parse import unquote

def detect_xss(response, payload, elapsed_time, context_signatures, original_res=None):
    """
    XSS 탐지 로직:
    1. 인코딩된 안전한 반사(Safe Reflection)를 제거
    2. 남은 텍스트에서 실행 가능한 형태의 마커(Raw Marker)가 있는지 확인
    3. 위험한 태그/이벤트 핸들러 문맥(Context)이 살아있는지 확인
    """
    evidences = []
    res_text = response.text
    payload_value = payload.value
    # payloads.py와 동일한 마커 정의
    marker = "XSSDAAAAvunXSSSAAAA"

    # [1] 안전한 반사값(Scrubbing) 제거
    # 서버가 정상적으로 필터링/인코딩을 했다면 이 부분은 무해함
    scrubbed_text = res_text
    
    # HTML 엔티티 인코딩된 버전들 생성 및 제거
    safe_variants = [
        html.escape(payload_value),                        # 기본 엔티티 (&lt; 등)
        html.escape(payload_value).replace("'", "&#x27;"), # 싱글 쿼테이션 변형
        payload_value.replace("<", "&lt;").replace(">", "&gt;"),
        unquote(payload_value) # URL 디코딩된 형태가 그대로 나오는지 확인하기 위해 제거 대상에서 제외하거나 별도 처리
    ]
    
    for var in filter(None, set(safe_variants)):
        scrubbed_text = scrubbed_text.replace(var, "[SAFE_REFLECTION_REMOVED]")

    # [2] 위험 문맥 시그니처 매칭 (context_patterns.json 활용)
    # <script, onerror=, javascript: 등이 인코딩되지 않고 남아있는지 확인
    has_dangerous_context = False
    for pattern in context_signatures:
        if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
            has_dangerous_context = True
            evidences.append(f"[Context] Dangerous pattern matched: {pattern}")
            break

    # --- 탐지 로직 시작 ---

    # 1. 마커 검증
    # 인코딩된 안전한 값들을 다 지웠음에도 마커가 남아있다면 -> 인코딩되지 않은 원본 노출!
    if marker.lower() in scrubbed_text.lower():
        if has_dangerous_context:
            # 위험한 태그나 속성이 살아있는 채로 마커가 발견됨 (실행 가능성 높음)
            evidences.append(f"[Execution] Raw XSS marker '{marker}' found in executable context")
        else:
            # 태그는 없으나 마커가 원본 그대로 노출 (Plain-text Reflection)
            evidences.append(f"[Reflection] Raw XSS marker '{marker}' found without encoding")

    # 2. 불리언 기반 탐지 (구조적 변화)
    # 페이로드 주입 후 페이지의 응답 길이나 구조가 크게 변했는지 확인
    if original_res:
        original_len = len(original_res.text)
        current_len = len(res_text)
        if original_len > 0:
            diff_ratio = abs(original_len - current_len) / original_len
            if diff_ratio > 0.15: # XSS로 인해 대량의 코드가 삽입되거나 페이지가 깨진 경우
                evidences.append(f"[Boolean] Large structural change detected ({diff_ratio:.1%})")

    is_vulnerable = len(evidences) > 0
    return is_vulnerable, evidences