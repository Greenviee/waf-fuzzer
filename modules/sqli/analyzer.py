import re
import html
from urllib.parse import unquote

def detect_sqli(response, payload, elapsed_time, exploit_signatures, syntax_signatures, mismatch_signatures, original_res=None):

    # 1단계: 단일 응답을 분석하여 취약점 증거 수집
    evidences = []
    res_text = response.text
    
    current_status = getattr(response, "status", getattr(response, "status_code", None))
    orig_status = getattr(original_res, "status", getattr(original_res, "status_code", None)) if original_res else None
    orig_elapsed = getattr(original_res, "elapsed_time", getattr(getattr(original_res, "elapsed", object()), "total_seconds", lambda: 0.0)()) if original_res else 0.0

    attack_type = payload.attack_type.lower()
    payload_value = payload.value
    marker = "SVSDAAAAvunVASDAAAA"

    # [1] 문법 오류 식별 및 영역 제거
    has_syntax_error = False
    scrubbed_text = res_text
    for pattern in syntax_signatures:
        if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
            has_syntax_error = True
            scrubbed_text = re.sub(pattern, "[FULL_SYNTAX_ERROR_REMOVED]", scrubbed_text, flags=re.I | re.DOTALL)

    # [2] 직접 반사 제거
    payload_variants = [payload_value, unquote(payload_value), html.escape(payload_value)]
    for var in filter(None, set(payload_variants)):
        scrubbed_text = scrubbed_text.replace(var, "[DIRECT_REFLECTION_REMOVED]")

    # 1. 시간 기반 탐지
    timing_keywords = ["sleep(", "waitfor delay", "pg_sleep", "benchmark(", "dbms_pipe.receive_message"]
    has_timing_intent = any(k in payload_value.lower() for k in timing_keywords)
    is_time_related = "time" in attack_type or "stacked" in attack_type or has_timing_intent
    if is_time_related and elapsed_time >= (4.5 + orig_elapsed):
        evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")

    # 2. 실행 에러 및 DBMS 불일치 판별
    has_execution_error = False
    for pattern in exploit_signatures:
        if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
            evidences.append(f"[Error] SQL Execution Error: {pattern}")
            has_execution_error = True
            break

    if not has_execution_error:
        for pattern in mismatch_signatures:
            if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
                evidences.append(f"[Potential] DBMS Mismatch Error: {pattern}")
                break

    # 3. 마커 검증
    marker_lower = marker.lower()
    if marker_lower in res_text.lower() and marker_lower in scrubbed_text.lower():
        if has_syntax_error or evidences:
            evidences.append(f"[Error] SQLi execution marker confirmed in DB output")
        else:
            evidences.append(f"[Reflection] SQLi marker confirmed as DB execution result")

    # 4. 불리언 기반 탐지
    if not evidences and not has_syntax_error and original_res:
        is_legit_status = current_status == 200 or current_status == orig_status
        is_generic_error = current_status in [400, 401, 403, 404, 405, 406, 500]

        if is_legit_status and not is_generic_error:
            orig_text_lower = original_res.text.lower()
            curr_text_lower = scrubbed_text.lower()
            if len(orig_text_lower) > 0:
                diff_bytes = abs(len(original_res.text) - len(res_text))
                if diff_bytes > 0:
                    evidences.append(f"[Boolean] Content length changed by {diff_bytes} bytes")
                
                blind_keywords = ["exists", "missing", "found", "success", "failed", "invalid", "true", "false"]
                for kw in blind_keywords:
                    if (kw in orig_text_lower) != (kw in curr_text_lower):
                        evidences.append(f"[Boolean] Blind keyword '{kw}' state inverted")
                        break

    return len(evidences) > 0, evidences, has_syntax_error

async def verify_sqli_logic(response, payload, original_res, requester, is_vuln_1st, evidences, has_syntax_error):

    #2단계: 추가 요청을 통해 취약점 확정
    if not requester or not original_res:
        return is_vuln_1st, evidences

    val = payload.value
    
    # [A] 1차 탐지에서 변화가 감지된 경우
    if is_vuln_1st:
        # 강한 증거가 이미 있다면 추가 검증 없이 확정
        if any(tag in str(evidences) for tag in ["[Error]", "[Time]", "[Reflection]"]):
            return True, evidences

        # 전략 1: 구문 복구 테스트 (Syntax Fix)
        if val.strip().endswith("'") or val.strip().endswith('"'):
            fix_res = await requester(val + " -- ")
            if is_similar(fix_res.text, original_res.text):
                return True, evidences + ["[Verified] Syntax Fix Test"]

        # 전략 2: 논리 패턴 반전 (Logic Swapping)
        logic_pattern = r"(['\"]?\w+['\"]?)\s*=\s*\1"
        if re.search(logic_pattern, val):
            false_payload = re.sub(logic_pattern, "1=2", val)
            false_res = await requester(false_payload)
            if not is_similar(false_res.text, response.text):
                return True, evidences + ["[Verified] Logic Swapping (True!=False)"]

    # [B] 변화 미감지 시 삼각 비교
    elif not has_syntax_error:
        logic_pattern = r"(['\"]?\w+['\"]?)\s*=\s*\1"
        if re.search(logic_pattern, val) or "1=1" in val:
            # 거짓 페이로드 생성
            false_payload = re.sub(logic_pattern, "1=2", val) if re.search(logic_pattern, val) else val.replace("1=1", "1=2")
            
            if false_payload != val:
                false_res = await requester(false_payload)
                # 원본(참)과는 같고, 거짓과는 확연히 다를 때
                if is_similar(response.text, original_res.text) and not is_similar(response.text, false_res.text):
                    return True, ["[Verified] Blind SQLi (Baseline==True and True!=False)"]

    return False, []

def is_similar(text1: str, text2: str) -> bool:
    """미세한 차이를 잡기 위한 유사도 판정 (1.5%)"""
    if not text1 or not text2: return False
    l1, l2 = len(text1), len(text2)
    diff = abs(l1 - l2)
    return (diff / max(l1, l2)) < 0.015