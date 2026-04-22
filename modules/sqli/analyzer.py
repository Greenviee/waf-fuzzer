import re
import os
import json
from core.models import Payload
from modules.base_module import BaseModule
from modules.sqli.payloads import get_sqli_payloads

class SQLiModule(BaseModule):
    def __init__(self):
        # 부모 클래스(BaseModule)의 생성자 호출
        super().__init__("SQL Injection")
        # 에러 시그니처 정규식 리스트 로드
        self.error_signatures = self._load_error_signatures()

    def _load_error_signatures(self):
        """sql_errors.json 파일에서 정규식 리스트를 불러옵니다."""
        file_path = os.path.join("config", "payloads", "sql_errors.json")
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[-] SQL 에러 시그니처 로드 실패: {e}")
        return []

    def get_payloads(self) -> list[Payload]:
        """
        payloads.py에 구현된 get_sqli_payloads() 함수를 호출하여 
        치환이 완료된 Payload 객체 리스트를 반환합니다.
        """
        return get_sqli_payloads()

    def analyze(self, response, payload: Payload, elapsed_time: float, original_res=None):
        """
        퍼징 엔진에서 호출하는 핵심 분석 함수입니다.
        발견된 모든 취약점 징후를 수집하여 (bool, list) 형태로 반환합니다.
        """
        evidences = []
        res_text = response.text
        
        # 1. 시간 기반 탐지 (Time-based / Stacked)
        # SQLmap 페이로드 치환값 5초를 기준으로 4.5초 이상 지연 시 탐지
        if "SQLi-Time" in payload.attack_type or "SQLi-Stacked" in payload.attack_type:
            if elapsed_time >= 4.5:
                evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")

        # 2. 에러 기반 탐지 (Error-based)
        # 로드된 정규식 패턴과 응답 본문을 매칭
        for pattern in self.error_signatures:
            try:
                if re.search(pattern, res_text, re.IGNORECASE | re.DOTALL):
                    evidences.append(f"[Error] SQL signature matched: {pattern}")
                    break 
            except re.error:
                continue

        # 3. 데이터 반사 탐지 (Union / Inline Query)
        # 주입한 'vun' 문자열이 응답에 그대로 나타나는지 확인
        if "SQLi-Union" in payload.attack_type or "SQLi-Inline" in payload.attack_type:
            target_str = "vun"
            if target_str in res_text:
                evidences.append(f"[Reflection] Injected value '{target_str}' found in response")

        # 4. 불리언 기반 탐지 (Boolean-based Blind)
        # '거짓' 조건 페이로드일 때 응답 길이가 원래와 10% 이상 차이나는지 분석
        if "SQLi-Boolean" in payload.attack_type and original_res:
            original_len = len(original_res.text)
            current_len = len(res_text)
            
            if original_len > 0:
                diff_ratio = abs(original_len - current_len) / original_len
                if diff_ratio > 0.1:
                    evidences.append(f"[Boolean] Length changed: {original_len} -> {current_len} ({diff_ratio:.1%})")

        # 최종 결과 반환: (취약 여부, 발견된 증거 리스트)
        is_vulnerable = len(evidences) > 0
        return is_vulnerable, evidences