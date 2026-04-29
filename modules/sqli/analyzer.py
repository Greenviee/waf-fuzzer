import re
import html
from urllib.parse import unquote

def detect_sqli(response, payload, elapsed_time, exploit_signatures, syntax_signatures, mismatch_signatures, original_res=None):
    evidences = []
    res_text = response.text
    
    current_status = getattr(response, "status", getattr(response, "status_code", None))
    orig_status = getattr(original_res, "status", getattr(original_res, "status_code", None)) if original_res else None
    orig_elapsed = getattr(original_res, "elapsed_time", getattr(getattr(original_res, "elapsed", object()), "total_seconds", lambda: 0.0)()) if original_res else 0.0

    attack_type = payload.attack_type.lower()
    payload_value = payload.value
    marker = "SVSDAAAAvunVASDAAAA"

    has_syntax_error = False
    has_execution_error = False
    has_potential_mismatch = False

    # [1] 문법 오류 식별 및 영역 제거
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

    # 1. 시간 기반 탐지
    timing_keywords = ["sleep(", "waitfor delay", "pg_sleep", "benchmark(", "dbms_pipe.receive_message"]
    has_timing_intent = any(k in payload_value.lower() for k in timing_keywords)
    is_time_related = "time" in attack_type or "stacked" in attack_type or has_timing_intent
    if is_time_related and elapsed_time >= (4.5 + orig_elapsed):
        evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")

    # 2. 실행 에러 및 DBMS 불일치 판별
    for pattern in exploit_signatures:
        if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
            evidences.append(f"[Error] SQL Execution Error: {pattern}")
            has_execution_error = True
            break

    if not has_execution_error:
        for pattern in mismatch_signatures:
            if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
                evidences.append(f"[Potential] DBMS Mismatch Error: {pattern}")
                has_potential_mismatch = True
                break

    # 3. 마커 검증
    marker_lower = marker.lower()
    if marker_lower in res_text.lower() and marker_lower in scrubbed_text.lower():
        if has_syntax_error or has_execution_error:
            evidences.append(f"[Error] SQLi execution marker confirmed in DB output")
        else:
            evidences.append(f"[Reflection] SQLi marker confirmed in legitimate content")

    # 4. 불리언 기반 탐지
    if (not evidences or has_potential_mismatch) and not has_syntax_error and original_res:
        if current_status != orig_status:
            evidences.append(f"[Boolean] Status Code changed: {orig_status} -> {current_status}")

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
    if not requester or not original_res:
        return is_vuln_1st, evidences

    val = payload.value
    res_text = response.text
    orig_text = original_res.text
    is_true_legit = is_similar_pure(res_text, orig_text)

    # [A] 1차 탐지에서 변화가 감지된 경우
    if is_vuln_1st:
        if any(tag in str(evidences) for tag in ["[Error]", "[Time]", "[Reflection]"]):
            return True, evidences

        # 참 조건이 원본과 비슷할 때만 수행
        if is_true_legit:
            # 전략 1: 구문 복구 테스트 (Quote 복구)
            if val.strip().endswith("'") or val.strip().endswith('"'):
                fix_res = await requester(val + " -- ")
                if is_similar_pure(fix_res.text, orig_text):
                    return True, evidences + ["[Verified] Syntax Fix Test"]

            # 전략 2: 논리 패턴 반전
            logic_pattern = r"(['\"]?\w+['\"]?)\s*=\s*\1"
            if re.search(logic_pattern, val) or "1=1" in val:
                false_payload = val.replace("1=1", "1=2") if "1=1" in val else re.sub(logic_pattern, "1=2", val)
                false_res = await requester(false_payload)
                if not is_similar(false_res.text, res_text):
                    return True, evidences + ["[Verified] Logic Swapping (True!=False)"]

    # [B] 변화 미감지 시
    elif not has_syntax_error:
        logic_pattern = r"(['\"]?\w+['\"]?)\s*=\s*\1"
        if re.search(logic_pattern, val) or "1=1" in val:
            false_payload = val.replace("1=1", "1=2") if "1=1" in val else re.sub(logic_pattern, "1=2", val)
            if false_payload != val:
                false_res = await requester(false_payload)
                if is_true_legit and not is_similar(false_res.text, res_text):
                    return True, ["[Verified] Blind SQLi (Baseline==True and True!=False)"]

    return False, []

def is_similar(text1: str, text2: str) -> bool:
    if not text1 or not text2: return False
    l1, l2 = len(text1), len(text2)
    diff = abs(l1 - l2)
    return (diff / max(l1, l2)) < 0.015

def _get_pure_text(html_content: str) -> str:
    if not html_content:
        return ""
    # 1. Script 및 Style 내용 제거
    text = re.sub(r'<(script|style).*?>.*?</\1>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    # 2. HTML 태그 제거
    text = re.sub(r'<[^>]+?>', ' ', text)
    # 3. HTML 엔티티 변환 (&nbsp; 등)
    text = html.unescape(text)
    # 4. 연속된 공백 및 줄바꿈 정리
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def is_similar_pure(text1: str, text2: str) -> bool:
    pure1 = _get_pure_text(text1)
    pure2 = _get_pure_text(text2)
    
    if not pure1 and not pure2: return True
    if not pure1 or not pure2: return False
    
    diff = abs(len(pure1) - len(pure2))
    return (diff / max(len(pure1), len(pure2))) < 0.015