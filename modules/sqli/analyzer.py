import re
import html
from urllib.parse import unquote
from difflib import SequenceMatcher

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

def get_text_ratio(text1: str, text2: str) -> float:
    pure1 = _get_pure_text(text1)
    pure2 = _get_pure_text(text2)
    
    if not pure1 and not pure2: return 1.0
    if not pure1 or not pure2: return 0.0
    
    # SequenceMatcher를 사용해 텍스트 유사도 계산
    return SequenceMatcher(None, pure1, pure2).ratio()

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

    # [1] 문법 오류 식별
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

    # 2. 에러 기반 탐지
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

        ratio = get_text_ratio(original_res.text, res_text)
        # 변화 감지
        if ratio < 1.0:
            evidences.append(f"[Boolean] Text similarity ratio: {ratio:.4f}")
            
            # 키워드 상태 반전 체크
            orig_pure = _get_pure_text(original_res.text).lower()
            curr_pure = _get_pure_text(res_text).lower()
            blind_keywords = ["exists", "missing", "found", "success", "failed", "invalid", "true", "false"]
            for kw in blind_keywords:
                if (kw in orig_pure) != (kw in curr_pure):
                    evidences.append(f"[Boolean] Blind keyword '{kw}' state inverted")
                    break

    return len(evidences) > 0, evidences, has_syntax_error

async def verify_sqli_logic(response, payload, original_res, requester, is_vuln_1st, evidences, has_syntax_error):
    if not requester or not original_res:
        return is_vuln_1st, evidences

    val = payload.value
    res_text = response.text
    orig_text = original_res.text
    
    pure_res = _get_pure_text(res_text)
    pure_orig = _get_pure_text(orig_text)
    
    true_ratio = get_text_ratio(orig_text, res_text)
    is_true_expanded = (len(pure_res) >= len(pure_orig) * 1.1) and (len(pure_res) - len(pure_orig) >= 20)
    is_true_legit = (true_ratio >= 0.985) or is_true_expanded

    if is_vuln_1st: # 변화 감지
        if any(tag in str(evidences) for tag in ["[Error]", "[Time]", "[Reflection]"]):
            return True, evidences

        if is_true_legit:
            # 전략 1: 구문 복구 테스트
            if val.strip().endswith("'") or val.strip().endswith('"'):
                fix_res = await requester(val + " -- ")
                # 복구된 응답이 원본과 유사한지 확인
                if get_text_ratio(fix_res.text, orig_text) >= 0.985:
                    return True, evidences + ["[Verified] Syntax Fix Test"]

            # 전략 2: 논리 패턴 반전
            logic_pattern = r"(['\"]?\w+['\"]?)\s*=\s*\1"
            if re.search(logic_pattern, val) or "1=1" in val:
                false_payload = val.replace("1=1", "1=2") if "1=1" in val else re.sub(logic_pattern, "1=2", val)
                false_res = await requester(false_payload)
                
                if get_text_ratio(false_res.text, res_text) < 0.995:
                    tag = "[Verified] Logic Swapping (Expansion)" if is_true_expanded else "[Verified] Logic Swapping (True!=False)"
                    return True, evidences + [tag]

    elif not has_syntax_error and (true_ratio >= 0.985): # 변화 미감지(Blind)
        logic_pattern = r"(['\"]?\w+['\"]?)\s*=\s*\1"
        if re.search(logic_pattern, val) or "1=1" in val:
            false_payload = val.replace("1=1", "1=2") if "1=1" in val else re.sub(logic_pattern, "1=2", val)
            if false_payload != val:
                false_res = await requester(false_payload)
                if get_text_ratio(false_res.text, res_text) < 0.995:
                    return True, ["[Verified] Blind SQLi (Baseline==True and True!=False)"]

    return False, []