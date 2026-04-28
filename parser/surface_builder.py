# core/surface_builder.py

import hashlib
import logging
import asyncio
from typing import Callable, Awaitable, Set, List, Union, Dict, Any
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup

from core.models import PageData, AttackSurface, HttpMethod, ParamLocation
from parser import form_extractor, link_extractor

logger = logging.getLogger(__name__)

SurfaceCallback = Callable[[AttackSurface], Union[Awaitable[None], None]]


class SurfaceBuilder:
    """
    공격 표면 빌더
    - 중복 파싱 방지 (Soup 재사용)
    - 동적 토큰(CSRF 등) 자동 병합
    - URL 쿼리스트링 중복 제거 및 파라미터 타입 평탄화 (Fuzzer 호환성)
    - 퍼저 콜백 직송
    """

    def __init__(self, fuzzer_callback: SurfaceCallback):
        self.fuzzer_callback = fuzzer_callback
        self._seen_signatures: Set[str] = set()

    @staticmethod
    def _generate_signature(surface: AttackSurface) -> str:
        """AttackSurface의 고유 해시 생성 (중복 제거용)"""
        param_keys = str(sorted(surface.parameters.keys()))
        raw = f"{surface.url}:{surface.method.value}:{surface.param_location.value}:{param_keys}"
        return hashlib.md5(raw.encode()).hexdigest()

    @staticmethod
    def _strip_query_string(url: str) -> str:
        """✅ [수정] URL에서 쿼리스트링(?id=1)을 제거하여 중복 결합 방지"""
        parsed = urlparse(url)
        # scheme, netloc, path, params, query(제거), fragment
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, '', parsed.fragment))

    @staticmethod
    def _normalize_parameters(raw_params: Dict[str, Any]) -> Dict[str, str]:
        """✅ [수정] Fuzzer에서 TypeError가 발생하지 않도록 모든 값을 단일 문자열로 평탄화"""
        normalized = {}
        for key, value in raw_params.items():
            if isinstance(value, list):
                # 리스트인 경우 첫 번째 값만 취하거나 빈 문자열 처리
                normalized[key] = str(value[0]) if value else ""
            else:
                normalized[key] = str(value)
        return normalized

    async def process_page(self, page_data: PageData) -> None:
        """PageData를 분석하여 AttackSurface를 추출하고 퍼저로 직배송"""
        surfaces: List[AttackSurface] = []

        # CrawlerEngine에서 만든 soup이 있으면 재사용, 없으면 1회만 파싱
        if isinstance(page_data.soup, BeautifulSoup):
            source_soup = page_data.soup
        else:
            source_soup = BeautifulSoup(page_data.html, 'html.parser')

        # ==========================================
        # 1. HTML Form 기반 AttackSurface 추출
        # ==========================================
        forms = form_extractor.extract_forms(source_soup, base_url=page_data.url)

        for form in forms:
            method_str = str(form.get('method', 'GET')).upper()
            try:
                method = HttpMethod(method_str)
            except ValueError:
                method = HttpMethod.GET

            loc = ParamLocation.BODY_FORM if method in (HttpMethod.POST, HttpMethod.PUT) \
                else ParamLocation.QUERY

            action_url = str(form.get('action')) if form.get('action') else str(page_data.url)

            # Form의 action URL에도 쿼리스트링이 있을 수 있으므로 정제
            safe_url = self._strip_query_string(action_url) if loc == ParamLocation.QUERY else action_url

            # 파라미터 평탄화(List 제거) 및 동적 토큰 병합
            parameters = self._normalize_parameters(form.get('parameters', {}))
            if page_data.dynamic_tokens:
                parameters.update(page_data.dynamic_tokens)

            surfaces.append(AttackSurface(
                url=safe_url,
                method=method,
                param_location=loc,
                parameters=parameters,
                headers=page_data.headers,
                cookies=page_data.cookies,
                source_url=str(page_data.url),
                description=f"Form (risk: {form.get('risk_level')}, tokens: {len(page_data.dynamic_tokens)})"
            ))

        # ==========================================
        # 2. URL 파라미터(Link) 기반 AttackSurface 추출
        # ==========================================
        links = link_extractor.extract_links(source_soup, base_url=page_data.url)

        for link in links:
            if not link.get('params'): continue

            method_str = str(link.get('method', 'GET')).upper()
            try:
                method = HttpMethod(method_str)
            except ValueError:
                method = HttpMethod.GET

            # ✅ URL 쿼리스트링 제거 (파라미터는 parameters 딕셔너리로 분리되어 넘어감)
            raw_url = str(link.get('url', ''))
            clean_url = self._strip_query_string(raw_url)

            # 파라미터 평탄화(List 제거) 및 동적 토큰 병합
            parameters = self._normalize_parameters(link.get('params', {}))
            if page_data.dynamic_tokens:
                parameters.update(page_data.dynamic_tokens)

            surfaces.append(AttackSurface(
                url=clean_url,
                method=method,
                param_location=ParamLocation.QUERY,
                parameters=parameters,
                headers=page_data.headers,
                cookies=page_data.cookies,
                source_url=str(page_data.url),
                description="Link Query Params"
            ))

        # ==========================================
        # 3. 중복 검증 및 퍼저 콜백 호출
        # ==========================================
        for surface in surfaces:
            if not surface.url: continue

            sig = self._generate_signature(surface)
            if sig in self._seen_signatures: continue

            self._seen_signatures.add(sig)

            logger.debug(f"[SurfaceBuilder] 퍼저로 전송: {surface.url}")

            result = self.fuzzer_callback(surface)
            if asyncio.iscoroutine(result):
                await result

    def get_stats(self) -> dict:
        return {"unique_surfaces_sent": len(self._seen_signatures)}