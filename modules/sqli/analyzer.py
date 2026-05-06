import re
import html
import asyncio
from urllib.parse import unquote
from difflib import SequenceMatcher

def _get_pure_text(html_content: str) -> str:
    """HTML 태그, 스크립트 등을 제거하여 순수 텍스트만 추출 (노이즈 제거)"""
    if not html_content:
        return ""
    text = re.sub(r'<(script|style).*?>.*?</\1>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[^>]+?>', ' ', text)
    text = html.unescape(text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def get_text_ratio(text1: str, text2: str) -> float:
    """순수 텍스트 유사도 비율 계산"""
    pure1 = _get_pure_text(text1)
    pure2 = _get_pure_text(text2)
    if not pure1 and not pure2: return 1.0
    if not pure1 or not pure2: return 0.0
    return SequenceMatcher(None, pure1, pure2).ratio()

def detect_sqli(response, payload, elapsed_time, exploit_signatures, syntax_signatures, mismatch_signatures, original_res=None):

    evidences = []
    res_text = response.text
    
    current_status = getattr(response, "status", getattr(response, "status_code", None))
    orig_status = getattr(original_res, "status", getattr(original_res, "status_code", None)) if original_res else None
    orig_elapsed = getattr(original_res, "elapsed_time", getattr(getattr(original_res, "elapsed", object()), "total_seconds", lambda: 0.0)()) if original_res else 0.0

    attack_type = payload.attack_type.lower()
    payload_value = payload.value
    marker_start = "SVSDAAAA"
    marker_stop = "VASDAAAA"
    dynamic_marker_pattern = re.compile(f"{marker_start}(.*?){marker_stop}", re.I | re.DOTALL)

    has_syntax_error = False
    has_execution_error = False
    has_potential_mismatch = False

    timing_keywords = ["sleep(", "waitfor delay", "pg_sleep", "benchmark(", "dbms_pipe.receive_message", "regexp_substring", "repeat("]
    has_timing_intent = any(k in payload_value.lower() for k in timing_keywords)
    is_time_related = "time" in attack_type or "stacked" in attack_type or has_timing_intent
    # 시간 페이로드 타임아웃 탐지
    if is_time_related and response is None:
        if elapsed_time >= 4.0:
            evidences.append(f"[Time] Request Timed Out: {elapsed_time:.2f}s")
        return len(evidences) > 0, evidences, False

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
    if is_time_related and elapsed_time >= (4.0 + orig_elapsed):
        evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")

    # 2. 에러 기반 탐지
    for pattern in exploit_signatures:
        if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
            marker_match = dynamic_marker_pattern.search(res_text)
            
            if marker_match:
                extracted_data = marker_match.group(1)
                evidences.append(f"[Error] SQL Execution Error (Marker Found: '{extracted_data}'): {pattern}")
                has_execution_error = True
            else:
                evidences.append(f"[ExecutionErr] SQL Execution Error (No Marker): {pattern}")
            break

    if not has_execution_error and not any("[ExecutionErr]" in e for e in evidences):
        for pattern in mismatch_signatures:
            if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
                evidences.append(f"[Mismatch] DBMS Mismatch Error: {pattern}")
                has_potential_mismatch = True
                break

    # 3. 마커 검증
    if not has_execution_error:
        # 동적 마커 패턴 검색
        marker_match_res = dynamic_marker_pattern.search(res_text)
        marker_match_scrubbed = dynamic_marker_pattern.search(scrubbed_text)

        if marker_match_res and marker_match_scrubbed:
            extracted_data = marker_match_res.group(1)
            
            if has_syntax_error or any("executionerr" in e.lower() for e in evidences):
                evidences.append(f"[Error] SQLi execution marker ('{extracted_data}') confirmed in DB output context")
                has_execution_error = True
            else:
                # 에러가 확인되지 않았는데 마커만 발견된 경우 단순 반사 또는 exploit_signatures에 없는 에러 메시지에서 데이터 추출
                evidences.append(f"[Reflection] SQLi marker ('{extracted_data}') confirmed in legitimate content")

    # 4. 불리언 기반 탐지
    if (not evidences or has_potential_mismatch or any("[ExecutionErr]" in e for e in evidences)) and not has_syntax_error and original_res:
        if current_status != orig_status:
            evidences.append(f"[Boolean] Status Code changed: {orig_status} -> {current_status}")

        ratio = get_text_ratio(original_res.text, res_text)
        if ratio < 0.995:
            evidences.append(f"[Boolean] Text similarity ratio: {ratio:.4f}")
            
            orig_pure = _get_pure_text(original_res.text).lower()
            curr_pure = _get_pure_text(res_text).lower()
            blind_keywords = ["exists", "missing", "found", "success", "failed", "invalid", "true", "false"]
            for kw in blind_keywords:
                if (kw in orig_pure) != (kw in curr_pure):
                    evidences.append(f"[Boolean] Blind keyword '{kw}' state inverted")
                    break

    return len(evidences) > 0, evidences, has_syntax_error

async def verify_sqli_logic(response, payload, original_res, requester, is_vuln_1st, evidences, has_syntax_error, syntax_signatures=None):
    if not requester or not original_res:
        return is_vuln_1st, evidences

    val = payload.value
    res_text = response.text
    orig_text = original_res.text
    orig_status = getattr(original_res, "status", getattr(original_res, "status_code", None))
    
    true_ratio = get_text_ratio(orig_text, res_text)
    pure_res = _get_pure_text(res_text)
    pure_orig = _get_pure_text(orig_text)
    
    logic_pattern = r"(['\"]?\w+['\"]?)\s*=\s*\1"
    is_true_expanded = (len(pure_res) >= len(pure_orig) * 1.1) and (len(pure_res) - len(pure_orig) >= 20)
    is_true_legit = (true_ratio >= 0.995) or is_true_expanded
    is_blind_candidate = (true_ratio >= 0.985) and (not is_true_legit)

    # [A] 1차 탐지에서 변화 감지
    if is_vuln_1st: 
        if any(tag in str(evidences) for tag in ["[Error]", "[Reflection]", "[Time]"]):
            return True, evidences

        # Path 1: 구조적 파손 검증 (주석 처리)
        if not is_true_legit and not is_blind_candidate:
            if val.strip().endswith("'") or val.strip().endswith('"'):
                fix_res = await requester(val + " -- ")
                ratio = get_text_ratio(fix_res.text, orig_text)
                if ratio >= 0.995:
                    return True, evidences + [f"[Verified] Syntax Fix Test(broken) Ratio: {ratio:.4f}"]

        # Path 2: 논리 반전 테스트
        has_logic = re.search(logic_pattern, val) or "1=1" in val
        
        if is_true_legit or is_blind_candidate or has_logic or any(tag in str(evidences) for tag in ["[ExecutionErr]"]):
            
            # 주석 복구 시도
            if val.strip().endswith("'") or val.strip().endswith('"'):
                fix_res = await requester(val + " -- ")
                fix_ratio = get_text_ratio(fix_res.text, orig_text)
                if fix_ratio >= 0.995:
                    return True, evidences + [f"[Verified] Syntax Fix Test Ratio: {fix_ratio:.4f}"]

            # 논리 반전 테스트
            if has_logic:
                false_payload = val.replace("1=1", "1=2") if "1=1" in val else re.sub(logic_pattern, "1=2", val)
                false_res = await requester(false_payload)
                false_res_text = false_res.text
                false_pure_res = _get_pure_text(false_res_text)
                false_status = getattr(false_res, "status", getattr(false_res, "status_code", None))
                
                # 거짓 응답 문법 에러 확인
                false_has_syntax_error = False
                if syntax_signatures:
                    for pattern in syntax_signatures:
                        if re.search(pattern, false_res_text, re.I | re.DOTALL):
                            false_has_syntax_error = True
                            break

                # [검증 1] 참 조건 응답에 데이터가 추가되었거나 baseline과 충분히 유사하고, 참 조건 응답과 거짓 조건 응답이 다른가
                if is_true_legit:
                    f_to_t_ratio = get_text_ratio(false_res.text, res_text)
                    if f_to_t_ratio < 0.99:
                        tag = f"[Verified] Logic Swapping (Expansion) Ratio: {f_to_t_ratio:.4f}" if is_true_expanded else f"[Verified] Logic Swapping (True!=False) Ratio: {f_to_t_ratio:.4f}"
                        return True, evidences + [tag]
                
                # [검증 2] 참 조건 응답이 baseline과 조금 다르고, 거짓 조건 응답은 같은가
                elif is_blind_candidate:
                    f_to_orig_ratio = get_text_ratio(false_res.text, orig_text)
                    if false_status == orig_status and f_to_orig_ratio >= 0.99:
                        return True, evidences + [f"[Verified] Inverted Logic Swapping (False==Baseline) Ratio: {f_to_orig_ratio:.4f}"]

                # [검증 3] 거짓 조건 응답에 데이터가 추가되었고, 참 조건 응답과 거짓조건 응답이 다른가
                is_false_expanded = (len(false_pure_res) >= len(pure_orig) * 1.1) and (len(false_pure_res) - len(pure_orig) >= 20)
                if not false_has_syntax_error and is_false_expanded:
                    f_to_orig_ratio = get_text_ratio(false_res.text, orig_text)
                    if f_to_orig_ratio < 0.99:
                        return True, evidences + [f"[Verified] Inverted Logic Swapping (False Expansion) Ratio: {f_to_orig_ratio:.4f}"]

    # [B]: 1차 탐지에서 변화 미감지
    elif not has_syntax_error and is_true_legit:
        if re.search(logic_pattern, val) or "1=1" in val:
            false_payload = val.replace("1=1", "1=2") if "1=1" in val else re.sub(logic_pattern, "1=2", val)
            false_res = await requester(false_payload)
            f_to_t_ratio = get_text_ratio(false_res.text, res_text)
            if f_to_t_ratio < 0.995:
                return True, [f"[Verified] Blind SQLi (Baseline==True and True!=False) Ratio: {f_to_t_ratio:.4f}"]

    return False, []