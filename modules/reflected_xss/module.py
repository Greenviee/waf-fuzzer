from __future__ import annotations

import random
import urllib.parse
from urllib.parse import urlparse, parse_qs
import logging
from typing import List, Any
import asyncio
import atexit
from concurrent.futures import ProcessPoolExecutor

from modules.base_module import BaseModule
from modules.reflected_xss.payloads import get_xss_payloads
from modules.reflected_xss.analyzer import detect_reflected_xss, Confidence
from core.models import Payload

logger = logging.getLogger(__name__)

_executor = None


def _get_executor():
    global _executor
    if _executor is None:
        _executor = ProcessPoolExecutor(max_workers=4)
        atexit.register(_executor.shutdown, wait=False)
    return _executor


class ReflectedXSSModule(BaseModule):
    """Reflected XSS 취약점 탐지 모듈"""

    def __init__(self, **kwargs):
        super().__init__("rxss")
        self.max_response_size: int = kwargs.get('max_response_size', 5 * 1024 * 1024)

        # evasion_level 범위 클램핑 (0~3 외 값 방어)
        raw_level = kwargs.get('evasion_level', 0)
        self.evasion_level: int = max(0, min(3, int(raw_level)))

        # 페이로드 폭발 제어: None이면 전체 사용, 정수면 무작위 샘플링
        self.max_payloads: int | None = kwargs.get('max_payloads', None)

        self.reported_findings = set()

        # 초기화 시점에 샘플링된 페이로드를 한 번만 생성하여 고정
        # → get_payloads() / get_payload_count() 중복 샘플링으로 인한
        #   페이로드 셋 불일치 버그 방지
        self._cached_payloads: List[Payload] = self._get_sampled_payloads()

    def _get_sampled_payloads(self) -> List[Payload]:
        """페이로드 로드 후 max_payloads 기준으로 샘플링 (1회만 호출됨)"""
        all_payloads = list(get_xss_payloads(evasion_level=self.evasion_level))

        if self.max_payloads is None or len(all_payloads) <= self.max_payloads:
            return all_payloads

        # HIGH 리스크 우선 보존 후 나머지 무작위 샘플링
        high = [p for p in all_payloads if getattr(p, 'risk_level', '') == 'HIGH']
        others = [p for p in all_payloads if getattr(p, 'risk_level', '') != 'HIGH']

        if len(high) >= self.max_payloads:
            sampled = random.sample(high, self.max_payloads)
        else:
            remaining = self.max_payloads - len(high)
            sampled = high + random.sample(others, min(remaining, len(others)))

        # 로그 메시지에 max_payloads 값 포함
        logger.info(
            f"[XSS] 페이로드 샘플링: {len(all_payloads)} → {len(sampled)}개 "
            f"(max_payloads={self.max_payloads})"
        )
        return sampled

    def get_payloads(self) -> List[Payload]:
        """캐싱된 페이로드 리스트 반환"""
        return self._cached_payloads

    def get_payload_count(self) -> int:
        """캐싱된 페이로드 수 반환"""
        return len(self._cached_payloads)

    async def analyze(
            self,
            response: Any,
            payload: Any,
            elapsed_time: float,
            original_res: Any = None,
            requester: Any = None,
    ) -> bool:
        """XSS 취약점 분석"""
        try:
            # Content-Type 필터 (JSON/XML 등 비 HTML 응답 스킵)
            content_type = str(getattr(response, 'content_type', '') or
                               getattr(response, 'headers', {}).get('content-type', '')).lower()

            # 빈 문자열('') 제거 및 로직 개선
            allowed_types = ('text/html', 'application/xhtml', 'text/javascript', 'application/javascript',
                             'text/plain')

            # Content-Type이 존재하는데 허용한 타입이 아니라면 분석 스킵 (json, image 등 차단)
            if content_type and not any(ct in content_type for ct in allowed_types):
                return False

            # 요청 URL 추출
            req_url = ""
            if requester and hasattr(requester, 'url'):
                req_url = str(requester.url)
            else:
                req_url = str(getattr(response, 'url', ''))

            # Parameter 추출
            target_parameter = self._extract_parameter(requester, response)

            if target_parameter == "unknown" and req_url:
                target_parameter = self._smart_recover_parameter(req_url, payload)

            # 응답 텍스트
            res_text = getattr(response, 'text', None)
            if not res_text:
                return False

            if len(res_text) > self.max_response_size:
                res_text = res_text[:self.max_response_size]

            orig_text = ""
            if original_res:
                orig_text = getattr(original_res, 'text', "") or ""
                if len(orig_text) > self.max_response_size:
                    orig_text = orig_text[:self.max_response_size]

            payload_value = getattr(payload, 'value', str(payload))

            # ========================================================
            # 분석 (ProcessPoolExecutor 적용 부분)
            # ========================================================
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                _get_executor(),
                detect_reflected_xss,
                res_text,
                orig_text,
                payload_value
            )

            # ========================================================
            # 중복 제거 (Dedup) 및 리포트 기록 부분
            # ========================================================
            if result.is_vulnerable and result.confidence != Confidence.NONE:

                # 500 에러 페이지 등급 강등 (노이즈 제거)
                status_code = getattr(response, 'status', getattr(response, 'status_code', 200))
                if status_code >= 500:
                    # 500 에러에서 반사된 경우 HIGH를 MEDIUM으로 강등
                    if result.confidence == Confidence.HIGH:
                        result.confidence = Confidence.MEDIUM
                    # 리포트 증거에 500 에러임을 표시
                    result.evidence = f"[500 Error Downgraded] {result.evidence}"
                    if result.confidence == Confidence.LOW:
                        return False

                # 1. 카테고리 추출 (대분류:소분류 까지 세분화)
                attack_type = getattr(payload, 'attack_type', '')
                parts = attack_type.split(':')

                # 'event_handler:auto_execution' 형태로 세분화하여 미탐 방지
                if len(parts) >= 3:
                    category = f"{parts[1]}:{parts[2]}"
                elif len(parts) == 2:
                    category = parts[1]
                else:
                    category = attack_type

                # 2. 쿼리를 제외한 순수 URL 추출
                raw_url = str(getattr(response, 'url', ''))
                parsed = urlparse(raw_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                # 3. 고유 키 생성 (URL + 파라미터 + 공격 종류)
                dedup_key = (base_url, target_parameter, category)

                # 4. 수첩에 없는 새로운 발견일 때만 리포트에 기록
                if dedup_key not in self.reported_findings:
                    self.reported_findings.add(dedup_key)
                    self._attach_metadata(payload, result, target_parameter, response)
                    return True
                else:
                    return False  # 중복 공격이면 무시함

            return False

        except Exception as e:
            logger.error(f"[XSS] 분석 중 오류: {e}", exc_info=True)
            return False

    def _smart_recover_parameter(self, url: str, payload: Any) -> str:
        """URL에서 페이로드가 주입된 파라미터 역추적"""
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)

            if not query_params:
                return "unknown"

            raw_payload = payload if isinstance(payload, str) else getattr(payload, 'value', str(payload))
            clean_payload = urllib.parse.unquote(str(raw_payload))

            for key, values in query_params.items():
                for val in values:
                    clean_val = urllib.parse.unquote(str(val))

                    if clean_payload == clean_val:
                        logger.info(f"🎯 [스마트복구] 파라미터 '{key}' 발견 (정확 일치)")
                        return key

                    if len(clean_payload) > 3 and clean_payload in clean_val:
                        logger.info(f"🎯 [스마트복구] 파라미터 '{key}' 발견 (부분 일치)")
                        return key

            first_param = list(query_params.keys())[0]
            logger.warning(f"⚠️ 파라미터 특정 불가, '{first_param}' 사용")
            return first_param

        except Exception as e:
            logger.debug(f"스마트 복구 실패: {e}")
            return "unknown"

    def _extract_parameter(self, requester: Any, response: Any) -> str:
        """Parameter 추출"""
        if requester is not None:
            if hasattr(requester, 'current_param') and requester.current_param:
                return str(requester.current_param)
            if hasattr(requester, 'parameter') and requester.parameter:
                return str(requester.parameter)
            if hasattr(requester, 'meta'):
                meta = requester.meta
                if isinstance(meta, dict):
                    param = meta.get('parameter') or meta.get('param')
                    if param:
                        return str(param)
                else:
                    param = getattr(meta, 'parameter', None) or getattr(meta, 'param', None)
                    if param:
                        return str(param)
        return "unknown"

    def _attach_metadata(self, payload: Any, result, parameter: str, response: Any) -> None:
        """결과 메타데이터 첨부"""
        
        pass
