from core.models import Payload
from modules.base_module import BaseModule
from modules.xss.payloads import get_xss_payloads

class XSSModule(BaseModule):
    def __init__(self):
        super().__init__("Cross-Site Scripting")

    def get_payloads(self) -> list[Payload]:
        return get_xss_payloads()

    def detect_xss(self, res, payload: Payload) -> bool:
        """XSS 탐지: 페이로드가 응답 바디에 그대로 포함되었는지 확인"""
        # HTML 엔티티 필터링 우회 여부 확인을 위해 원본 페이로드 값 비교
        if payload.value in res.text:
            return True
        return False

    def analyze(self, response, payload: Payload, elapsed_time: float, original_res=None) -> bool:
        return self.detect_xss(response, payload)