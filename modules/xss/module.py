import os
import json
from modules.base_module import BaseModule
from modules.xss.payloads import get_xss_payloads
from modules.xss.analyzer import detect_xss

class XSSModule(BaseModule):
    def __init__(
        self,
        *,
        enable_polyglots: bool = True,  # 여러 문맥을 한 번에 뚫는 페이로드 포함 여부
        include_blind_xss: bool = False, # 외부 로그 서버를 이용한 Blind XSS 포함 여부
        max_payloads: int = 0           # 사용할 페이로드 최대 개수 (0은 무제한)
    ):
        super().__init__("Cross-Site Scripting")
        
        # 위험한 HTML/JS 문맥 패턴 로드 (SQLi의 syntax_errors와 유사한 역할)
        self.context_signatures = self._load_json("context_patterns.json")
        
        self.enable_polyglots = enable_polyglots
        self.include_blind_xss = include_blind_xss
        self.max_payloads = max_payloads

    def _load_json(self, filename):
        file_path = os.path.join("config", "payloads", filename)
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[-] [{self.name}] {filename} load failed: {e}")
        return []

    def get_payloads(self):
        """설정에 따라 필터링된 XSS 페이로드 리스트를 반환합니다."""
        base_payloads = get_xss_payloads()
        
        if self.max_payloads > 0:
            base_payloads = base_payloads[:self.max_payloads]
            
        return base_payloads

    def analyze(self, response, payload, elapsed_time, original_res=None) -> bool:
        """
        analyzer.py의 detect_xss를 호출하여 
        안전하게 인코딩된 결과와 실제 실행 가능한 코드를 구분합니다.
        """
        is_vuln, evidences = detect_xss(
            response=response,
            payload=payload,
            elapsed_time=elapsed_time,
            context_signatures=self.context_signatures,
            original_res=original_res
        )
        
        # evidences는 리포터 모듈에서 상세 증거로 활용 가능합니다.
        return is_vuln