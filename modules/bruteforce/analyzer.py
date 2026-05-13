from __future__ import annotations

from urllib.parse import urlparse


def _contains_any(text: str, keywords: list[str]) -> bool:
    text_lower = text.lower()
    return any(keyword.lower() in text_lower for keyword in keywords if keyword)


def detect_login_success(
    response,
    payload,
    original_res=None,
    success_keywords: list[str] | None = None,
    fail_keywords: list[str] | None = None,
) -> tuple[bool, list[str]]:
    """
    Analyze response changes to estimate whether credential stuffing succeeded.
    """
    evidences: list[str] = []
    success_markers = success_keywords or []
    fail_markers = fail_keywords or []

    res_text = getattr(response, "text", "") or ""
    res_status = int(getattr(response, "status", 0) or 0)
    res_url = str(getattr(response, "url", "") or "")
    transport_error = getattr(response, "error", None)

    # 네트워크/타임아웃 등으로 본문이 없을 때 길이 비교 휴리스틱이 오탐하기 쉬움.
    if transport_error or (res_status == 0 and not res_text.strip()):
        return False, []

    # 1) Failure-first rule:
    # If explicit failure markers are still present, treat as failed immediately.
    if fail_markers and _contains_any(res_text, fail_markers):
        return False, []

    # 2) Explicit success keywords — only when NEW vs baseline (avoid nav chrome:
    #    "Logout", "dashboard" 링크 등은 로그인 실패 응답에도 동일하게 붙는 경우가 많음).
    if success_markers and _contains_any(res_text, success_markers):
        base_text_for_kw = ""
        if original_res is not None:
            base_text_for_kw = getattr(original_res, "text", "") or ""
        if not base_text_for_kw or not _contains_any(base_text_for_kw, success_markers):
            evidences.append("[Keyword] Success keyword found in response body")

    # 3) Compare with baseline response (wrong credential baseline recommended).
    if original_res is not None:
        base_text = getattr(original_res, "text", "") or ""
        base_status = int(getattr(original_res, "status", 0) or 0)
        base_url = str(getattr(original_res, "url", "") or "")

        if base_status != res_status and res_status in (301, 302, 303, 307, 308):
            evidences.append(
                f"[Diff] Status changed after payload: {base_status} -> {res_status}"
            )

        # Compare only URL path, not full URL.
        # Query always changes in brute-force runs, which would cause constant false positives.
        if base_url and res_url:
            base_path = urlparse(base_url).path
            res_path = urlparse(res_url).path
            if base_path and res_path and base_path != res_path:
                evidences.append(
                    f"[Diff] Landing path changed after payload: {base_path} -> {res_path}"
                )

        if fail_markers:
            base_has_fail = _contains_any(base_text, fail_markers)
            now_has_fail = _contains_any(res_text, fail_markers)
            if base_has_fail and not now_has_fail:
                evidences.append("[Keyword] Failure message disappeared from response")

        if base_text:
            diff_ratio = abs(len(base_text) - len(res_text)) / max(len(base_text), 1)
            if diff_ratio >= 0.30:
                evidences.append(f"[Length] Response size changed significantly ({diff_ratio:.1%})")

    return len(evidences) > 0, evidences
