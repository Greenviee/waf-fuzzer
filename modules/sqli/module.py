import os
import json
import urllib.parse
import re
import dataclasses
import random
from typing import Any, Iterator
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

    def get_payloads(self) -> Iterator[Any]:

        # 1. 원본 소스 로드
        all_raw = get_sqli_payloads()
        
        # 2. 인덱스 기반 분류
        fast_indices = []
        time_indices = []

        for i, p in enumerate(all_raw):
            if self._is_time_payload(p):
                time_indices.append(i)
            else:
                fast_indices.append(i)

        # 3. 랜덤 부여된 인덱스로 시간 기반 페이로드 샘플링
        selected_time_indices = []
        if self.include_time_based and time_indices:
            random.seed(self.random_seed)
            limit = self.max_time_payloads if self.max_time_payloads > 0 else len(time_indices)
            limit = min(limit, len(time_indices))
            selected_time_indices = random.sample(time_indices, limit)

        # 추가 리스트 없이 순회하며 생성
        for idx in (fast_indices + selected_time_indices):
            p = all_raw[idx]
            
            # 우회 기법 필요할 때만 적용
            evasion_value = self._apply_evasion_by_level(p.value)
            yield dataclasses.replace(p, value=evasion_value)

        del all_raw
        del fast_indices
        del time_indices

    def get_payload_count(self) -> int:

        all_raw = get_sqli_payloads()
        
        fast_count = 0
        time_total_count = 0

        # 페이로드 추가 시 한 번만 개수 카운트
        for p in all_raw:
            if self._is_time_payload(p):
                time_total_count += 1
            else:
                fast_count += 1
        
        selected_time_count = 0
        if self.include_time_based and time_total_count > 0:
            limit = self.max_time_payloads if self.max_time_payloads > 0 else time_total_count
            selected_time_count = min(limit, time_total_count)
            
        return fast_count + selected_time_count

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
        is_vuln_1st, evidences, has_syntax_error = detect_sqli(
            response=response,
            payload=payload,
            elapsed_time=elapsed_time,
            exploit_signatures=self.exploit_signatures,
            syntax_signatures=self.syntax_signatures,
            mismatch_signatures=self.mismatch_signatures,
            original_res=original_res
        )

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
            # Payload can be a frozen/slots dataclass. In that case attaching
            # ad-hoc metadata raises AttributeError; keep scan running anyway.
            try:
                object.__setattr__(payload, 'last_evidences', final_evidences)
            except (AttributeError, TypeError):
                pass
            return True
        return False