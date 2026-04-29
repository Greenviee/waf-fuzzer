import html
from core.models import Payload
from modules.base_module import BaseModule
from modules.xss.payloads import get_xss_payloads

class XSSModule(BaseModule):
    def __init__(self):
        super().__init__("Cross-Site Scripting")

    def get_payloads(self) -> list[Payload]:
        return get_xss_payloads()

    def detect_xss(self, res, payload: Payload) -> bool:
        res_text = res.text
        p_value = payload.value
        p_type = payload.attack_type

        # [방식 1] 단순 반사 확인 및 엔티티 인코딩 체크
        # 페이로드가 응답에 아예 없으면 탈락
        if p_value not in res_text:
            return False

        # [방식 2] HTML Tag Context 분석 (가장 흔함)
        if p_type == "XSS-Tag":
            # <script> 가 &lt;script&gt; 로 치환되었는지 확인
            # 치환되지 않고 원래 값 그대로 있다면 취약!
            if p_value in res_text:
                return True

        # [방식 3] Attribute Context 분석 (속성 탈출)
        elif p_type == "XSS-Attribute":
            # 페이로드에 포함된 따옴표(")나 꺽쇠(>)가 살아있는지 확인
            # 예: " onclick="alert(1) 가 입력되었을 때 그대로 출력되는지
            if p_value in res_text:
                return True

        # [방식 4] Script Context 분석 (JS 코드 삽입)
        elif p_type == "XSS-Script":
            # 자바스크립트 구문 기호인 세미콜론(;)이나 주석(//)이 살아있는지 확인
            if p_value in res_text:
                return True

        # [방식 5] 포괄적 필터링 우회 여부 확인 (Generic)
        # 중요 특수문자들이 인코딩되지 않고 출력된다면 잠재적 위험
        critical_chars = ["<", ">", '"', "'"]
        if all(c in p_value for c in critical_chars): # 페이로드에 특수문자가 포함된 경우
            # 인코딩된 형태(&lt; 등)가 없고 원본이 있다면 취약
            encoded_char = html.escape(p_value)
            if encoded_char not in res_text and p_value in res_text:
                return True

        return False

    def analyze(self, response, payload: Payload, elapsed_time: float, original_res=None) -> bool:
        return self.detect_xss(response, payload)