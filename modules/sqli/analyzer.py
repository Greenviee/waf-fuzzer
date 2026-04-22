import re
import os
import json
from core.models import Payload
from modules.base_module import BaseModule
from modules.sqli.payloads import get_sqli_payloads

class SQLiModule(BaseModule):
    def __init__(self):
        super().__init__("SQL Injection")
        # 에러 시그니처 로드
        self.error_signatures = self._load_error_signatures()

    def _load_error_signatures(self):
        """추출된 SQL 에러 정규식 리스트를 JSON 파일에서 불러옵니다."""
        file_path = os.path.join("config", "payloads", "sql_errors.json")
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[-] 에러 시그니처 로드 실패: {e}")
        return []

    def get_payloads(self) -> list[Payload]:
        """sqli.txt에서 페이로드 리스트를 가져옵니다."""
        return get_sqli_payloads()

    def analyze(self, response, payload: Payload, elapsed_time: float, original_res=None):
        """
        다양한 기법(Time, Error, Reflection, Boolean)을 복합적으로 분석하여 
        발견된 모든 증거(evidences)를 수집합니다.
        """
        evidences = []
        res_text = response.text
        
        # 1. 시간 기반 탐지 (Time-based / Stacked)
        # SQLmap 페이로드에 [SLEEPTIME]이 5로 치환되어 있으므로 4.5초를 기준으로 잡음
        if "SQLi-Time" in payload.attack_type or "SQLi-Stacked" in payload.attack_type:
            if elapsed_time >= 4.5:
                evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")

        # 2. 에러 기반 탐지 (Error-based)
        # 제공된 정규식 리스트를 사용하여 모든 응답에서 에러 패턴 검색
        for pattern in self.error_signatures:
            try:
                # 정규식 매칭 (re.IGNORECASE로 대소문자 무시, re.DOTALL로 줄바꿈 포함 매칭)
                if re.search(pattern, res_text, re.IGNORECASE | re.DOTALL):
                    evidences.append(f"[Error] SQL signature matched: {pattern}")
                    # 에러는 하나만 발견해도 충분하므로 중복 수집 방지 위해 break
                    break 
            except re.error:
                # 정규식 패턴 자체에 오류가 있을 경우 건너뜀
                continue

        # 3. 데이터 반사 탐지 (Union / Inline Query)
        # 추출 시 [RANDSTR]을 'vun'으로, [RANDNUM]을 '1'로 치환함
        if payload.attack_type in ["SQLi-Union", "SQLi-Inline"]:
            target_str = "vun"
            if target_str in res_text:
                evidences.append(f"[Reflection] Injected value '{target_str}' found in response")

        # 4. 불리언 기반 탐지 (Boolean-based Blind)
        # 원본 응답(original_res)과 현재 응답의 길이 차이를 분석
        if "SQLi-Boolean" in payload.attack_type and original_res:
            original_len = len(original_res.text)
            current_len = len(res_text)
            
            if original_len > 0:
                diff_ratio = abs(original_len - current_len) / original_len
                # 응답 길이가 10% 이상 차이가 나면 논리 구조 변화로 간주
                if diff_ratio > 0.1:
                    evidences.append(f"[Boolean] Length changed: {original_len} -> {current_len} ({diff_ratio:.1%})")

        # 취약점 발견 여부 판단 (증거가 하나라도 있으면 True)
        is_vulnerable = len(evidences) > 0
        return is_vulnerable, evidences