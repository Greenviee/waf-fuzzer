import os
import json
import urllib.parse
import re
import dataclasses
import random
from typing import List, Any
from modules.base_module import BaseModule
from modules.sqli.payloads import get_sqli_payloads
from modules.sqli.analyzer import detect_sqli, verify_sqli_logic 

class SQLiModule(BaseModule):
    def __init__(self, **kwargs):
        super().__init__("SQL Injection")
        self.exploit_signatures = self._load_json("exploit_errors.json")
        self.syntax_signatures = self._load_json("syntax_errors.json")
        self.mismatch_signatures = self._load_json("mismatch_errors.json")
        
        self.evasion_level = kwargs.get('evasion_level', 0)
        self.include_time_based = kwargs.get('include_time_based', False)
        self.max_time_payloads = kwargs.get('max_time_payloads', 0)
        self.random_seed = kwargs.get('random_seed', 37)

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

        processed_payloads = []
        for p in fast_payloads:
            new_value = self._apply_evasion_by_level(p.value)
            processed_payloads.append(dataclasses.replace(p, value=new_value))
        return processed_payloads

    def _apply_evasion_by_level(self, value: str) -> str:
        if self.evasion_level <= 0: return value
        if self.evasion_level >= 1:
            value = value.replace("SELECT", "sElEcT").replace("UNION", "uNiOn")
            value = value.replace("AND", "aNd").replace("OR", "oR")
            value = value.replace("CASE", "cAsE").replace("WHEN", "wHeN")
        if self.evasion_level >= 2:
            value = value.replace(" ", "/**/")
        if self.evasion_level >= 3:
            value = urllib.parse.quote(urllib.parse.quote(value))
            value += "%00"
        return value

    async def analyze(self, response, payload, elapsed_time, original_res=None, requester=None):
        # 1. 표면 분석
        is_vuln_1st, evidences, has_syntax_error = detect_sqli(
            response=response,
            payload=payload,
            elapsed_time=elapsed_time,
            exploit_signatures=self.exploit_signatures,
            syntax_signatures=self.syntax_signatures,
            mismatch_signatures=self.mismatch_signatures,
            original_res=original_res
        )

        # 2. 논리 분석
        final_hit, final_evidences = await verify_sqli_logic(
            response=response,
            payload=payload,
            original_res=original_res,
            requester=requester,
            is_vuln_1st=is_vuln_1st,
            evidences=evidences,
            has_syntax_error=has_syntax_error
        )

        if final_hit:
            object.__setattr__(payload, 'last_evidences', final_evidences)
            return True

        return False