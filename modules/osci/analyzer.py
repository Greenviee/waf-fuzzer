import re
import html
import asyncio
from urllib.parse import unquote
from difflib import SequenceMatcher

def _remove_direct_reflection(text: str, payload_value: str) -> str:
    scrubbed = text
    payload_variants = [
        payload_value,
        unquote(payload_value),
        unquote(unquote(payload_value)),
        html.escape(payload_value),
        html.unescape(payload_value)
    ]
    for variant in filter(None, set(payload_variants)):
        scrubbed = scrubbed.replace(variant, "[DIRECT_REFLECTION_REMOVED]")
    return scrubbed

def _analyze_marker_context(text: str, marker: str) -> str:
    positions = [m.start() for m in re.finditer(re.escape(marker), text)]
    for pos in positions:
        start = max(0, pos - 100)
        end = min(len(text), pos + len(marker) + 100)
        context = text[start:end]
        if re.search(r'<[^>]*' + re.escape(marker) + r'[^>]*>', context):
            return "reflection_html"
        error_patterns = [
            r'error.*?' + re.escape(marker),
            r'invalid.*?' + re.escape(marker),
            r'not\s+allowed.*?' + re.escape(marker),
            r'forbidden.*?' + re.escape(marker),
            r'denied.*?' + re.escape(marker),
            r'failed.*?' + re.escape(marker)
        ]
        if any(re.search(p, context, re.I) for p in error_patterns):
            return "reflection_error"
    return "execution_output"

def detect_osci(response, payload, elapsed_time, original_res=None):
    evidences = []
    attack_type = getattr(payload, "attack_type", "").lower()
    payload_value = getattr(payload, "value", "")
    is_time_based = "time-based" in attack_type or "time" in attack_type

    marker = "SVSDAAAA"
    arithmetic_sum = 100

    # [1] 타임아웃 탐지
    if is_time_based and response is None:
        if elapsed_time >= 10.0:
            evidences.append(f"[Time] Request timed out: {elapsed_time:.2f}s")
            return True, evidences

    # [2] Time-based 탐지
    if is_time_based and response:
        orig_elapsed = 0.0
        if original_res:
            orig_elapsed = getattr(original_res, "elapsed_time",
                                   getattr(getattr(original_res, "elapsed", object()),
                                           "total_seconds", lambda: 0.0)())
        threshold = 3.0
        if elapsed_time >= (threshold + orig_elapsed):
            evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s (baseline: {orig_elapsed:.2f}s)")
            return True, evidences

    # [3] In-band 탐지
    if response and not is_time_based:
        res_text = response.text

        if original_res and marker in original_res.text:
            evidences.append(f"[False Positive] Marker exists in baseline response")
            return False, evidences

        # 직접 반사 제거
        scrubbed_text = _remove_direct_reflection(res_text, payload_value)
        marker_count_original = res_text.count(marker)
        marker_count_scrubbed = scrubbed_text.count(marker)

        arithmetic_pattern = re.compile(rf"{marker}\D*(\d+)\D*{marker}", re.I | re.DOTALL)
        matches_scrubbed = arithmetic_pattern.findall(scrubbed_text)

        # Case 1: 완전한 마커 산술 결과 검출
        if matches_scrubbed:
            for match in matches_scrubbed:
                if int(match) == arithmetic_sum:
                    evidences.append(f"[Output] Command execution confirmed (Arithmetic): {marker}...{match}...{marker}")
                    return True, evidences

        # Case 2: 잘린 마커 대응
        fallback_pattern = re.compile(rf"{marker}\D*({arithmetic_sum})", re.I | re.DOTALL)
        if fallback_pattern.search(scrubbed_text):
            evidences.append(f"[Output] Command execution detected (Clipped Output): Found {marker} followed by {arithmetic_sum}")
            return True, evidences

        # Case 3: 다중 마커 검출
        if marker_count_scrubbed >= 3:
            context_type = _analyze_marker_context(scrubbed_text, marker)
            if context_type == "execution_output":
                evidences.append(f"[Output] Multiple command outputs confirmed in clean context")
                return True, evidences
            else:
                evidences.append(f"[Output] Potential execution: {marker_count_scrubbed} markers in {context_type} context")
                return True, evidences

        # Case 4: 단일 마커 검출
        if marker_count_scrubbed >= 1:
            if marker_count_original > marker_count_scrubbed:
                evidences.append(f"[Reflection] Input reflection detected")
                return False, evidences
            context_type = _analyze_marker_context(scrubbed_text, marker)
            if context_type == "execution_output":
                evidences.append(f"[Output] Single marker found (requires verification)")
                return True, evidences
            else:
                evidences.append(f"[Reflection] Marker in {context_type} context")
                return False, evidences

        if marker_count_original > 0 and marker_count_scrubbed == 0:
            evidences.append(f"[Reflection] Marker only in direct reflection (false positive)")
            return False, evidences

    return len(evidences) > 0, evidences

async def verify_osci_logic(response, payload, original_res, requester, is_hit, evidences):
    if not requester or not is_hit:
        return is_hit, evidences

    marker = "SVSDAAAA"
    payload_value = getattr(payload, "value", "")

    # [A] 강한 증거 확정
    strong_evidence_tags = [
        "Command execution confirmed",
        "Multiple command outputs",
        "Request timed out"
    ]
    if any(tag in str(evidences) for tag in strong_evidence_tags):
        return True, evidences

    # [B] 시간 지연 경계값 재검증 비활성화
    if "[Time]" in str(evidences):
        """
        time_match = re.search(r'delayed: ([\d.]+)s', str(evidences))
        if time_match:
            delay_time = float(time_match.group(1))
            
            # 4~5초 사이 경계값인 경우 재검증
            if 3.0 < delay_time < 5.0:
                try:
                    retry_res = await requester(payload_value)
                    retry_elapsed = getattr(retry_res, "elapsed_time", 0.0)
                    
                    if retry_elapsed >= 4.0:
                        evidences.append(f"[Verified] Delay confirmed on retry: {retry_elapsed:.2f}s")
                        return True, evidences
                    else:
                        return False, ["[False Positive] Delay not reproducible"]
                except Exception:
                    pass
        """
        return True, evidences

    # [C] 단일/이중 마커 재검증
    if "requires verification" in str(evidences):
        try:
            # 동일 페이로드 재전송 (일관성 확인)
            retry_res = await requester(payload_value)
            retry_text = retry_res.text

            # 반사 제거
            scrubbed_retry = _remove_direct_reflection(retry_text, payload_value)

            if marker in scrubbed_retry:
                context_type = _analyze_marker_context(scrubbed_retry, marker)
                if context_type == "execution_output":
                    evidences.append("[Verified] Marker consistently appears in clean context")
                    return True, evidences
                else:
                    evidences.append(f"[Verified] Marker appears but in {context_type} context")
                    return True, evidences
            else:
                return False, ["[False Positive] Marker was one-time reflection"]
        except Exception:
            pass

    # [D] 산술 결과 변형 검증 비활성화
    if "Arithmetic" in str(evidences) or "Clipped Output" in str(evidences):
        """
        try:
            # N 값을 다른 값으로 변경 (100 → 80)
            # 단, 페이로드 구조에 따라 치환 위치가 다를 수 있음
            modified_payload = payload_value
            
            # [N] 플레이스홀더 치환
            if "[N]" in modified_payload:
                modified_payload = modified_payload.replace("100", "80")
            
            mod_res = await requester(modified_payload)
            
            # 80이 출력되는지 확인
            if "SVSDAAAA80SVSDAAAA" in mod_res.text:
                evidences.append("[Verified] Arithmetic mutation confirmed (100→80)")
                return True, evidences
            
        except Exception:
            pass
        """
        return True, evidences

    return is_hit, evidences