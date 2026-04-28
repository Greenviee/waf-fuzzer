import os
import json
import urllib.parse
import re
import dataclasses
import random
from typing import List, Any
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
        random_seed: int = 37
    ):
        super().__init__("SQL Injection")
        self.exploit_signatures = self._load_json("exploit_errors.json")
        self.syntax_signatures = self._load_json("syntax_errors.json")
        self.mismatch_signatures = self._load_json("mismatch_errors.json")
        
        self.enable_case_bypass = enable_case_bypass
        self.enable_null_byte_bypass = enable_null_byte_bypass
        self.enable_keyword_split_bypass = enable_keyword_split_bypass
        self.enable_double_url_encoding = enable_double_url_encoding
        self.enable_unicode_escape = enable_unicode_escape
        self.include_time_based = include_time_based
        self.max_time_payloads = max_time_payloads
        self.random_seed = random_seed

    def _load_json(self, filename):
        file_path = os.path.join("config", "payloads", filename)
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[-] [{self.name}] {filename} load failed: {e}")
        return []

    def _is_time_payload(self, payload) -> bool:
        attack_type = str(getattr(payload, "attack_type", "")).lower()
        return "time" in attack_type or "stacked" in attack_type

    def get_payloads(self):
        all_raw = get_sqli_payloads()
        
        fast_payloads = []
        time_pool = []

        include_time = self.include_time_based
        for p in all_raw:
            if self._is_time_payload(p):
                if include_time:
                    time_pool.append(p)
            else:
                fast_payloads.append(p)
                
        print(f"[*] SQLi Payloads: Total={len(all_raw)}, Fast={len(fast_payloads)}, TimePool={len(time_pool)}")

        if include_time and time_pool:
            random.seed(self.random_seed)
            random.shuffle(time_pool)
            
            limit = self.max_time_payloads if self.max_time_payloads > 0 else len(time_pool)
            fast_payloads.extend(time_pool[:limit])
            
            del time_pool

        processed_payloads = []
        for p in fast_payloads:
            new_value = self._apply_bypass_techniques(p.value)
            processed_payloads.append(dataclasses.replace(p, value=new_value))
            
        return processed_payloads

    def _apply_bypass_techniques(self, value: str) -> str:
        if self.enable_case_bypass:
            value = value.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN")
        if self.enable_null_byte_bypass:
            value += "%00"
        if self.enable_double_url_encoding:
            value = urllib.parse.quote(urllib.parse.quote(value))
        return value

    def _mutate_to_false(self, value: str) -> str:
        # 참(1=1)을 거짓(1=2)으로 변경
        return value.replace("1=1", "1=2").replace("4231=4231", "4231=4232")

    async def analyze(self, response, payload, elapsed_time, original_res=None, requester=None):
        
        #원본-참-거짓 삼각 대조 
        is_vuln, evidences = detect_sqli(
            response=response, 
            payload=payload, 
            elapsed_time=elapsed_time, 
            exploit_signatures=self.exploit_signatures, 
            syntax_signatures=self.syntax_signatures,
            mismatch_signatures=self.mismatch_signatures,
            original_res=original_res
        )
        
        # [A] 변화 감지 시 (강한 증거 우선 처리)
        if is_vuln:
            has_strong_evidence = any(tag in str(evidences) for tag in ["[Error]", "[Time]", "[Reflection]"])
            if has_strong_evidence:
                object.__setattr__(payload, 'last_evidences', evidences)
                return True

            # 약한 증거(Boolean)만 있다면 추가 검증 수행
            if requester and original_res:
                val = payload.value
                
                # 전략 1: 구문 복구 (id=1' -> id=1' -- )
                if val.strip().endswith("'") or val.strip().endswith('"'):
                    fix_res = await requester(val + " -- ")
                    if self._is_similar(fix_res.text, original_res.text):
                        object.__setattr__(payload, 'last_evidences', evidences + ["[Verified] Syntax Fix Test"])
                        return True

                # 전략 2: 논리 반전 (X=X -> 1=2)
                logic_pattern = r"(['\"]?\w+['\"]?)\s*=\s*\1"
                if re.search(logic_pattern, val):
                    false_payload = re.sub(logic_pattern, "1=2", val)
                    false_res = await requester(false_payload)
                    if not self._is_similar(false_res.text, response.text):
                        object.__setattr__(payload, 'last_evidences', evidences + ["[Verified] Logic Swapping (True!=False)"])
                        return True

        # [B] 변화 미감지 시 (Blind SQLi '참' 조건 가능성 확인)
        else:
            if requester and original_res:
                val = payload.value
                logic_pattern = r"(['\"]?\w+['\"]?)\s*=\s*\1"
                
                if re.search(logic_pattern, val) or "1=1" in val:
                    if re.search(logic_pattern, val):
                        false_payload = re.sub(logic_pattern, "1=2", val)
                    else:
                        false_payload = val.replace("1=1", "1=2")
                    
                    if false_payload != val:
                        false_res = await requester(false_payload)
                        if self._is_similar(response.text, original_res.text) and not self._is_similar(response.text, false_res.text):
                            object.__setattr__(payload, 'last_evidences', ["[Verified] Blind SQLi (Baseline==True and True!=False)"])
                            return True

        return False

    def _is_similar(self, text1: str, text2: str) -> bool:
        """미세한 차이를 잡기 위한 엄격한 유사도 판정 (1.5%)"""
        if not text1 or not text2: return False
        l1, l2 = len(text1), len(text2)
        diff = abs(l1 - l2)
        return (diff / max(l1, l2)) < 0.015