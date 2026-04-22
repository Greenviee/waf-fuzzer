import os
import json
from modules.base_module import BaseModule
from modules.sqli.payloads import get_sqli_payloads
from modules.sqli.analyzer import detect_sqli # 분리한 분석 함수 임포트

class SQLiModule(BaseModule):
    def __init__(self):
        super().__init__("SQL Injection")
        self.error_signatures = self._load_error_signatures()

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
        return get_sqli_payloads()

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