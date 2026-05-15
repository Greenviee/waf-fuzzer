import os
import json
import urllib.parse
import re
import dataclasses
import random
import asyncio
from dataclasses import dataclass
from typing import Iterator, Any, Tuple, List, Optional, Iterable

from modules.base_module import BaseModule
from modules.osci.payloads import get_osci_payloads
from modules.osci.analyzer import detect_osci, verify_osci_logic
from core.models import Payload

@dataclass(frozen=True, slots=True)
class OSCIInternalPayload(Payload):
    _is_serial: bool = False
    _real_time_value: Optional[str] = None

class OSCIModule(BaseModule):
    def __init__(self, **kwargs):
        super().__init__("OS Command Injection")
        
        self.evasion_level = kwargs.get('evasion_level', 0)
        self.include_time_based = kwargs.get('include_time_based', False)
        self.max_time_payloads = kwargs.get('max_time_payloads', 0)
        self.random_seed = kwargs.get('random_seed', 37)
        self.target_os = kwargs.get('target_os', 'Unix')
        
        self._global_time_lock = asyncio.Lock()
        self._fast_per_param = 0
        self._known_targets = set()
        self._total_fast_expected = 0
        self._global_fast_completed = 0
        self._counter_lock = asyncio.Lock()
        
        # 이벤트 기반 장벽을 통해 시간 페이로드 직렬 처리
        self._barrier_event = asyncio.Event()
        self._time_attack_in_flight = 0
        self._time_phase_active = False

    def _is_time_payload(self, payload: Payload) -> bool:
        attack_type = str(getattr(payload, "attack_type", "")).lower()
        return "time-based" in attack_type or "time" in attack_type

    def get_target_parameters(self, surface: Any, all_params: Iterable[str]) -> Iterable[str]:
        if self._fast_per_param == 0:
            self.get_payload_count()
        params = list(all_params)
        url = getattr(surface, "url", "")
        method = getattr(surface, "method", "GET")
        for p in params:
            tid = (method, url, p)
            if tid not in self._known_targets:
                self._known_targets.add(tid)
                self._total_fast_expected += self._fast_per_param
        return params

    def get_payload_count(self) -> int:
        all_raw = get_osci_payloads()
        
        filtered = [p for p in all_raw if getattr(p, 'target_os', 'Unix') == self.target_os]
        
        fast_c = sum(1 for p in filtered if not self._is_time_payload(p))
        time_c = sum(1 for p in filtered if self._is_time_payload(p))
        
        selected_time_count = 0
        if self.include_time_based:
            limit = self.max_time_payloads if self.max_time_payloads > 0 else time_c
            selected_time_count = min(limit, time_c)
        
        multiplier = self.evasion_level + 1
        self._fast_per_param = fast_c * multiplier
        return self._fast_per_param + (selected_time_count * multiplier)

    def get_payloads(self) -> Iterator[Payload]:
        if self._fast_per_param == 0: 
            self.get_payload_count()

        all_raw = get_osci_payloads()
        
        filtered = [p for p in all_raw if getattr(p, 'target_os', 'Unix') == self.target_os]
        
        fast_indices = [i for i, p in enumerate(filtered) if not self._is_time_payload(p)]
        time_indices = [i for i, p in enumerate(filtered) if self._is_time_payload(p)]

        # 일반 페이로드 (병렬 처리)
        for level in range(self.evasion_level + 1):
            for idx in fast_indices:
                p = filtered[idx]
                yield OSCIInternalPayload(
                    value=self._apply_evasion_by_level(p.value, level),
                    attack_type=p.attack_type,
                    risk_level=p.risk_level,
                    target_os=p.target_os,
                    action_level=p.action_level,
                    _is_serial=False
                )

        # 시간 기반 페이로드 (직렬 처리)
        if self.include_time_based and time_indices:
            random.seed(self.random_seed)
            limit = self.max_time_payloads if self.max_time_payloads > 0 else len(time_indices)
            selected_indices = random.sample(time_indices, min(limit, len(time_indices)))
            for level in range(self.evasion_level + 1):
                for idx in selected_indices:
                    p = filtered[idx]
                    yield OSCIInternalPayload(
                        value="1",
                        attack_type=p.attack_type,
                        risk_level=p.risk_level,
                        target_os=p.target_os,
                        action_level=p.action_level,
                        _is_serial=True,
                        _real_time_value=self._apply_evasion_by_level(p.value, level)
                    )

    def _apply_evasion_by_level(self, value: str, level: int) -> str:

        action_level = getattr(self.current_payload, "action_level", "SHELL")

        if level == 0:
            return value
        
        # Level 1: 공백 우회
        if level >= 1:
            if self.target_os == "Unix":
                value = value.replace(" ", "$IFS")
            else:
                if "PS" in action_level:
                    pass
                else:
                    value = value.replace(" ", ",")
        
        # Level 2: 키워드 난독화
        if level >= 2:
            if self.target_os == "Unix":
                value = value.replace("echo", "ec\\ho")
                value = value.replace("cat", "c\\at")
            else:
                value = value.replace("echo", "ec^ho")
                value = value.replace("set", "s^et")
                if "PS" in action_level:
                    value = value.replace("Write-Output", "W'rite-O'utput")
        
        # Level 3: URL 인코딩
        if level >= 3:
            value = urllib.parse.quote(value)
        
        return value

    async def analyze(self, response: Any, payload: Any, elapsed_time: float, 
                      original_res: Any = None, requester: Any = None) -> Tuple[bool, List[str], Any]:
        is_serial = getattr(payload, "_is_serial", False)

        # [A] 일반 페이로드 분석 (병렬)
        if not is_serial:
            # 시간 페이즈 종료까지 대기
            while self._time_phase_active:
                await asyncio.sleep(2.0)

            try:
                is_hit, evidences = detect_osci(
                    response=response,
                    payload=payload,
                    elapsed_time=elapsed_time,
                    original_res=original_res
                )
                
                if is_hit:
                    final_hit, final_evidences = await verify_osci_logic(
                        response, payload, original_res, requester, is_hit, evidences
                    )
                    return final_hit, final_evidences, payload
                
                return is_hit, evidences, payload
            finally:
                async with self._counter_lock:
                    self._global_fast_completed += 1
                    if self._global_fast_completed >= self._total_fast_expected and self._total_fast_expected > 0:
                        if not self._barrier_event.is_set():
                            self._barrier_event.set()

        # [B] 시간 기반 페이로드 분석 (직렬)
        if is_serial and requester:
            async with self._counter_lock:
                self._time_attack_in_flight += 1

            try:
                # 1. 장벽 대기
                if not self._barrier_event.is_set():
                    try:
                        # 25초 후 데드락 해제
                        await asyncio.wait_for(self._barrier_event.wait(), timeout=25.0)
                    except asyncio.TimeoutError:
                        if not self._time_phase_active:
                            pass
                    
                if not self._time_phase_active:
                    self._time_phase_active = True

                # 2. 전역 직렬 실행 락
                async with self._global_time_lock:
                    real_val = getattr(payload, "_real_time_value", "test")
                    actual_payload = dataclasses.replace(payload, value=real_val)
                    
                    try:
                        start_ts = asyncio.get_event_loop().time()
                        real_res = await requester(real_val)
                        real_elapsed = asyncio.get_event_loop().time() - start_ts
                        
                        # 서버 회복 대기
                        await asyncio.sleep(4.5)

                        is_hit, evidences = detect_osci(
                            response=real_res,
                            payload=actual_payload,
                            elapsed_time=real_elapsed,
                            original_res=original_res
                        )

                        if is_hit and "[Time]" not in str(evidences):
                            is_hit, evidences = await verify_osci_logic(
                                real_res, actual_payload, original_res, requester, is_hit, evidences
                            )
                        return is_hit, evidences, actual_payload

                    except asyncio.TimeoutError:
                        is_hit, evidences = detect_osci(
                            response=None,
                            payload=actual_payload,
                            elapsed_time=15.0,
                            original_res=original_res
                        )
                        return True, evidences, actual_payload
            finally:
                async with self._counter_lock:
                    self._time_attack_in_flight -= 1
                    if self._time_attack_in_flight == 0:
                        if self._time_phase_active:
                            self._barrier_event.clear()
                            self._time_phase_active = False

        return False, [], payload