import re
import html
from urllib.parse import unquote

def detect_sqli(response, payload, elapsed_time, exploit_signatures, syntax_signatures, mismatch_signatures, original_res=None, requester=None):
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

    # --- 탐지 로직 시작 ---

    # 1. 시간 기반 탐지 (원본 응답 시간 대비 지연 확인)
    timing_keywords = ["sleep(", "waitfor delay", "pg_sleep", "benchmark(", "dbms_pipe.receive_message"]
    has_timing_intent = any(k in payload_value.lower() for k in timing_keywords)
    is_time_related = "time" in attack_type or "stacked" in attack_type or has_timing_intent

    if is_time_related and elapsed_time >= (4.5 + orig_elapsed):
        evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s (Baseline: {orig_elapsed:.2f}s)")

    # 2. 실행/런타임 에러 및 DBMS 불일치 판별
    has_execution_error = False
    
    # [A] 공격 성공 시그니처 확인
    for pattern in exploit_signatures:
        if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
            evidences.append(f"[Error] SQL Execution Error: {pattern}")
            has_execution_error = True
            break

    # [B] DBMS 미스매치 확인
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

    # 4. 불리언 기반 탐지 (다른 증거가 없을 때만 수행)
    if not evidences and not has_syntax_error and original_res:
        # 상태코드가 200이거나 원본과 같을 때만 본문 비교
        is_legit_status = current_status == 200 or current_status == orig_status
        is_generic_error = current_status in [400, 401, 403, 404, 405, 406, 500]

        if is_legit_status and not is_generic_error:
            orig_text_lower = original_res.text.lower()
            curr_text_lower = scrubbed_text.lower()

            if len(orig_text_lower) > 0:
                diff_bytes = abs(len(original_res.text) - len(res_text))
                if diff_bytes > 0:
                    evidences.append(f"[Boolean] Content length changed by {diff_bytes} bytes")
                
                # 키워드 반전 확인
                blind_keywords = ["exists", "missing", "found", "success", "failed", "invalid", "true", "false"]
                for kw in blind_keywords:
                    if (kw in orig_text_lower) != (kw in curr_text_lower):
                        evidences.append(f"[Boolean] Blind keyword '{kw}' state inverted")
                        break

    is_vulnerable = len(evidences) > 0
    return is_vulnerable, evidences