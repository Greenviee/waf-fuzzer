# core/surface_builder.py

import hashlib
import logging
import asyncio
from typing import Callable, Awaitable, Set, List, Union
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

    async def process_page(self, page_data: PageData) -> None:
        """PageData를 분석하여 AttackSurface를 추출하고 퍼저로 직배송"""
        surfaces: List[AttackSurface] = []

        # ✅ [최적화] CrawlerEngine에서 만든 soup이 있으면 재사용, 없으면 1회만 파싱
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

            safe_url = str(form.get('action')) if form.get('action') else str(page_data.url)

            # ✨ [데이터 병합] 크롤러가 수집한 동적 토큰을 공격 파라미터에 주입
            parameters = form.get('parameters', {}).copy()
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

            # 링크 파라미터에도 동적 토큰 병합 (정규화된 문자열 타입)
            parameters = link.get('params', {}).copy()
            if page_data.dynamic_tokens:
                parameters.update(page_data.dynamic_tokens)

            surfaces.append(AttackSurface(
                url=str(link.get('url', '')),
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
