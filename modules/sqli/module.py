import os
import json
import urllib.parse
import re
import dataclasses

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
        self.exploit_signatures = self._load_json("exploit_errors.json")
        self.syntax_signatures = self._load_json("syntax_errors.json")
        
        self.enable_case_bypass = enable_case_bypass
        self.enable_null_byte_bypass = enable_null_byte_bypass
        self.enable_keyword_split_bypass = enable_keyword_split_bypass
        self.enable_double_url_encoding = enable_double_url_encoding
        self.enable_unicode_escape = enable_unicode_escape
        self.include_time_based = include_time_based
        self.max_time_payloads = max_time_payloads

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
        base_payloads = get_sqli_payloads()
        filtered_payloads = self._filter_slow_payloads(base_payloads)
        
        final_payloads = []
        for p in filtered_payloads:
            new_value = self._apply_bypass_techniques(p.value)
            new_payload = dataclasses.replace(p, value=new_value)
            final_payloads.append(new_payload)
        return final_payloads

    def _apply_bypass_techniques(self, value: str) -> str:
        if self.enable_case_bypass:
            value = value.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN")
        if self.enable_null_byte_bypass:
            value += "%00"
        if self.enable_double_url_encoding:
            value = urllib.parse.quote(urllib.parse.quote(value))
        return value

    def _filter_slow_payloads(self, payloads):
        if self.include_time_based:
            if self.max_time_payloads <= 0: return payloads
            time_payloads = []
            fast_payloads = []
            for payload in payloads:
                attack_type = str(getattr(payload, "attack_type", "")).lower()
                if "time" in attack_type or "stacked" in attack_type:
                    time_payloads.append(payload)
                else:
                    fast_payloads.append(payload)
            return fast_payloads + time_payloads[: self.max_time_payloads]

        return [p for p in payloads if "time" not in str(getattr(p, "attack_type", "")).lower() and "stacked" not in str(getattr(p, "attack_type", "")).lower()]

    
    def _mutate_to_false(self, value: str) -> str:
        # 참에서 거짓으로 치환
        false_value = value.replace("1=1", "1=2")
        return false_value
    
    async def analyze(self, response, payload, elapsed_time, original_res=None, requester=None):

        is_vuln, evidences = detect_sqli(
            response=response, 
            payload=payload, 
            elapsed_time=elapsed_time, 
            exploit_signatures=self.exploit_signatures, 
            syntax_signatures=self.syntax_signatures,
            original_res=original_res
        )
        
        # [A] 변화가 감지된 경우
        if is_vuln:
            # 1. 강한 증거(에러, 마커, 시간)
            has_strong_evidence = any(tag in str(evidences) for tag in ["[Error]", "[Time]", "[Reflection]"])
            if has_strong_evidence:
                object.__setattr__(payload, 'last_evidences', evidences)
                return True

            # 2. 약한 증거(Boolean)가 감지된 경우 (Fix Test/Safe Test 등 수행)
            if requester and original_res:
                val = payload.value
                
                # 1: 구문 복구 테스트 (Quote 하나로 깨진 경우)
                if val.strip().endswith("'") or val.strip().endswith('"'):
                    fix_payload = val + " -- "
                    res = await requester(fix_payload)
                    if self._is_similar(res.text, original_res.text):
                        object.__setattr__(payload, 'last_evidences', evidences + ["[Verified] Syntax Fix Test"])
                        return True

                # 2: 논리 패턴 반전 검색 (Regex Swap)
                logic_pattern = r"(['\"]?\w+['\"]?)\s*=\s*\1"
                if re.search(logic_pattern, val):
                    false_payload = re.sub(logic_pattern, "1=2", val)
                    res = await requester(false_payload)
                    if not self._is_similar(res.text, response.text): # 참 응답과 달라야 함
                        object.__setattr__(payload, 'last_evidences', evidences + ["[Verified] Logic Swapping (True!=False)"])
                        return True

        # [B] 변화가 감지되지 않은 경우 (Blind SQLi의 '참' 페이로드일 확률)
        else:
            if requester and original_res:
                val = payload.value
                logic_pattern = r"(['\"]?\w+['\"]?)\s*=\s*\1"
                if re.search(logic_pattern, val) or "1=1" in val:
                    false_payload = re.sub(logic_pattern, "1=2", val) if re.search(logic_pattern, val) else val.replace("1=1", "1=2")
                    
                    if false_payload != val:
                        false_res = await requester(false_payload)
                        if self._is_similar(response.text, original_res.text) and not self._is_similar(response.text, false_res.text):
                            object.__setattr__(payload, 'last_evidences', ["[Verified] Blind SQLi (Baseline==True and True!=False)"])
                            return True

        return False

    def _is_similar(self, text1: str, text2: str) -> bool:
        if not text1 or not text2: return False
        len1, len2 = len(text1), len(text2)
        diff = abs(len1 - len2)
        return (diff / max(len1, len2)) < 0.001

        return is_vuln