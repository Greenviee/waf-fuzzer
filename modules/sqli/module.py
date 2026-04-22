import os
import json
from modules.base_module import BaseModule
from modules.sqli.payloads import get_sqli_payloads
from modules.sqli.analyzer import detect_sqli # 분리한 분석 함수 임포트

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
        self.error_signatures = self._load_error_signatures()
        self.enable_case_bypass = enable_case_bypass
        self.enable_null_byte_bypass = enable_null_byte_bypass
        self.enable_keyword_split_bypass = enable_keyword_split_bypass
        self.enable_double_url_encoding = enable_double_url_encoding
        self.enable_unicode_escape = enable_unicode_escape
        self.include_time_based = include_time_based
        self.max_time_payloads = max_time_payloads

    def _load_error_signatures(self):
        file_path = os.path.join("config", "payloads", "sql_errors.json")
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[-] [{self.name}] Error signatures load failed: {e}")
        return []

    def get_payloads(self):
        base_payloads = get_sqli_payloads()
        filtered_payloads = self._filter_slow_payloads(base_payloads)
        # Mutator is intentionally disabled for fast DVWA-low test cycles.
        return filtered_payloads

    def _filter_slow_payloads(self, payloads):
        """
        Reduce scan time by excluding or limiting time/stacked payloads.
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
            return fast_payloads + time_payloads[: self.max_time_payloads]

        return [
            payload
            for payload in payloads
            if "time" not in str(getattr(payload, "attack_type", "")).lower()
            and "stacked" not in str(getattr(payload, "attack_type", "")).lower()
        ]

    def analyze(self, response, payload, elapsed_time, original_res=None) -> bool:
        """
        BaseModule 인터페이스에 맞춰 불리언 결과를 반환합니다.
        필요시 내부적으로 탐지된 증거들을 로그로 출력합니다.
        """
        is_vuln, evidences = detect_sqli(
            response=response, 
            payload=payload, 
            elapsed_time=elapsed_time, 
            error_signatures=self.error_signatures, 
            original_res=original_res
        )
        
        if is_vuln:
            # 발견된 증거들을 리스트 형태로 관리하거나 리포터 팀에 넘길 준비를 합니다.
            # 예: print(", ".join(evidences))
            pass
            
        return is_vuln