import logging
from modules.base_module import BaseModule
from modules.lfi.analyzer import detect_lfi
from modules.lfi.payloads import generate_payloads

logger = logging.getLogger(__name__)

class LFIModule(BaseModule):
    def __init__(self, evasion_level: int = 1):
        super().__init__("LFI")
        self.payloads = generate_payloads(evasion_level=evasion_level)

    def get_payloads(self):
        return self.payloads

    def analyze(self, response, payload, elapsed_time, original_res=None) -> bool:
        is_vuln, evidences = detect_lfi(
            response=response,
            payload=payload,
            elapsed_time=elapsed_time,
        )
        return is_vuln
