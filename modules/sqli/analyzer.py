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
        Payload 객체의 attack_type에 따라 다른 분석 기법 적용
        """
        # 1. 에러 메시지 기반 (공통 적용)
        error_signatures = ["sql syntax", "mysql_fetch", "native client", "ora-01756"]
        if any(sig in res.text.lower() for sig in error_signatures):
            return True

        # 2. 시간 지연 기반 (타입이 SQLi-Time일 때만 체크)
        if "SQLi-Time" in payload.attack_type:
            if elapsed_time >= 4.5:
                return True

        # 3. 논리 비교 기반 (타입이 SQLi-Boolean-False일 때만 체크)
        if "SQLi-Boolean-False" in payload.attack_type and original_res:
            if len(res.text) < len(original_res.text) * 0.9:
                return True

        return False

    def analyze(self, response, payload: Payload, elapsed_time: float, original_res=None) -> bool:
        return self.detect_sqli(response, payload, elapsed_time, original_res)