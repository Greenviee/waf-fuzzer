import os
import json
from modules.base_module import BaseModule
from modules.sqli.payloads import get_sqli_payloads
from modules.sqli.analyzer import detect_sqli 

class SQLiModule(BaseModule):
    def __init__(
        self,
        *,
        enable_case_bypass: bool = False,
        enable_null_byte_bypass: bool = False,
        enable_keyword_split_bypass: bool = False,
        enable_double_url_encoding: bool = False,
        enable_unicode_escape: bool = False,
        include_time_based: bool = False,
        max_time_payloads: int = 0,
    ):
        super().__init__("SQL Injection")
        
        # 두 가지 에러 시그니처를 각각 로드하여 오탐 방지 로직 지원
        self.exploit_signatures = self._load_json("exploit_errors.json")
        self.syntax_signatures = self._load_json("syntax_errors.json")
        
        # 설정값 유지
        self.enable_case_bypass = enable_case_bypass
        self.enable_null_byte_bypass = enable_null_byte_bypass
        self.enable_keyword_split_bypass = enable_keyword_split_bypass
        self.enable_double_url_encoding = enable_double_url_encoding
        self.enable_unicode_escape = enable_unicode_escape
        self.include_time_based = include_time_based
        self.max_time_payloads = max_time_payloads

    def _load_json(self, filename):
        """config/payloads/ 폴더에서 JSON 파일을 안전하게 로드합니다."""
        file_path = os.path.join("config", "payloads", filename)
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[-] [{self.name}] {filename} load failed: {e}")
        return []

    def get_payloads(self):
        """최종 조합된 페이로드를 가져오고 설정에 따라 필터링합니다."""
        base_payloads = get_sqli_payloads()
        filtered_payloads = self._filter_slow_payloads(base_payloads)
        return filtered_payloads

    def _filter_slow_payloads(self, payloads):
        """
        스캔 시간을 단축하기 위해 Time-based 페이로드를 제외하거나 개수를 제한합니다.
        """
        if self.include_time_based:
            if self.max_time_payloads <= 0:
                return payloads

            time_payloads = []
            fast_payloads = []
            for payload in payloads:
                attack_type = str(getattr(payload, "attack_type", "")).lower()
                if "time" in attack_type or "stacked" in attack_type:
                    time_payloads.append(payload)
                else:
                    fast_payloads.append(payload)
            # 설정된 max_time_payloads 개수만큼만 Time-based 페이로드 포함
            return fast_payloads + time_payloads[: self.max_time_payloads]

        # Time-based 제외 설정 시 일반 페이로드만 반환
        return [
            payload
            for payload in payloads
            if "time" not in str(getattr(payload, "attack_type", "")).lower()
            and "stacked" not in str(getattr(payload, "attack_type", "")).lower()
        ]

    def analyze(self, response, payload, elapsed_time, original_res=None) -> bool:
        """
        analyzer.py의 detect_sqli를 호출하여 
        단순 문법 에러와 실제 공격 성공을 구분한 결과 반환
        """
        # 분리된 두 세트의 시그니처를 analyzer에 전달
        is_vuln, evidences = detect_sqli(
            response=response, 
            payload=payload, 
            elapsed_time=elapsed_time, 
            exploit_signatures=self.exploit_signatures, 
            syntax_signatures=self.syntax_signatures,
            original_res=original_res
        )
        
        if is_vuln:
            # 발견된 상세 증거들을 로깅 (리포터에서 활용 가능)
            pass
            
        return is_vuln