from core.models import Payload
from modules.base_module import BaseModule
from modules.sqli.payloads import get_sqli_payloads

class SQLiModule(BaseModule):
    def __init__(self):
        super().__init__("SQL Injection")

    def get_payloads(self) -> list[Payload]:
        return get_sqli_payloads()

    def detect_sqli(self, res, payload: Payload, elapsed_time: float, original_res=None) -> bool:
        """
        보완된 SQLi 탐지 로직 (에러 시그니처 + 시간 + 불리언)
        """
        res_text = res.text.lower()

        # 1. 시그니처 기반 (Error-based)
        error_signatures = [
            "sql syntax", "mysql_fetch", "native client", 
            "ora-01756", "sqlite3.operationalerror", "unclosed quotation mark"
        ]
        if any(sig in res_text for sig in error_signatures):
            return True

        # 2. 시간 기반 (Time-based Blind)
        if "SQLi-Time" in payload.attack_type and elapsed_time >= 4.5:
            return True

        # 3. 논리 비교 기반 (Boolean-based Blind)
        if original_res and "SQLi-Boolean-False" in payload.attack_type:
            original_len = len(original_res.text)
            current_len = len(res.text)
            # 거짓 응답의 길이가 원본과 10% 이상 차이가 나면 의심
            if original_len > 0 and abs(original_len - current_len) / original_len > 0.1:
                return True

        return False

    def analyze(self, response, payload: Payload, elapsed_time: float, original_res=None) -> bool:
        return self.detect_sqli(response, payload, elapsed_time, original_res)