from __future__ import annotations

import re

from modules.file_upload.payloads import FilePayload

SUCCESS_SIGNATURES = [
    r"succes+fully uploaded",
    r"upload complete",
    r"file uploaded successfully",
    r"the file.+has been uploaded",
    r"saved to",
    r"uploads?/",
]

ERROR_KEYWORDS = [
    "failed",
    "invalid file",
    "not uploaded",
    "error",
    "not allowed",
    "forbidden file type",
]


def detect_file_upload(response, payload) -> tuple[bool, list[str]]:
    """
    Detect probable successful upload from response content.
    """
    if not isinstance(payload, FilePayload):
        return False, []

    evidences: list[str] = []
    res_text = response.text or ""
    res_lower = res_text.lower()

    if any(keyword in res_lower for keyword in ERROR_KEYWORDS):
        return False, evidences

    for pattern in SUCCESS_SIGNATURES:
        if re.search(pattern, res_lower, re.IGNORECASE):
            evidences.append(f"[SuccessSignature] matched: {pattern}")
            break

    if payload.filename.lower() in res_lower:
        evidences.append(f"[FilenameReflection] {payload.filename}")

    return (len(evidences) > 0), evidences
