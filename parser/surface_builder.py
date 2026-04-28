import hashlib
import logging
import asyncio
from typing import Callable, Awaitable, Set, List, Union
from bs4 import BeautifulSoup

from core.models import PageData, AttackSurface, HttpMethod, ParamLocation
from parser import form_extractor, link_extractor

logger = logging.getLogger(__name__)

# 퍼저 콜백 타입 정의
SurfaceCallback = Callable[[AttackSurface], Union[Awaitable[None], None]]


class SurfaceBuilder:
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
        """
        PageData를 분석하여 AttackSurface를 추출하고 퍼저로 직배송합니다.
        """
        surfaces: List[AttackSurface] = []

        # ✅ 반영 1: BeautifulSoup 객체를 한 번만 생성하여 재사용 (CPU 오버헤드 감소)
        soup = BeautifulSoup(page_data.html, 'html.parser')

        # ==========================================
        # 1. HTML Form 기반 AttackSurface 추출
        # ==========================================
        # 문자열 대신 이미 파싱된 soup 객체를 넘깁니다.
        forms = form_extractor.extract_forms(soup, base_url=page_data.url)

        for form in forms:
            method_str = str(form.get('method', 'GET')).upper()
            try:
                method = HttpMethod(method_str)
            except ValueError:
                method = HttpMethod.GET

            if method in (HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE):
                param_location = ParamLocation.BODY_FORM
            else:
                param_location = ParamLocation.QUERY

            action_url = form.get('action')
            safe_url = str(action_url) if action_url else str(page_data.url)

            # ✅ 반영 2: 크롤러가 수집해온 동적 토큰을 파라미터에 병합
            parameters = form.get('parameters', {}).copy()
            if page_data.dynamic_tokens:
                parameters.update(page_data.dynamic_tokens)

            surface = AttackSurface(
                url=safe_url,
                method=method,
                param_location=param_location,
                parameters=parameters,
                headers=page_data.headers,
                cookies=page_data.cookies,
                source_url=str(page_data.url),
                description=f"Form Input (risk: {form.get('risk_level', 'low')}, csrf: {form.get('has_csrf_token')})"
            )
            surfaces.append(surface)

        # ==========================================
        # 2. URL 파라미터(Link) 기반 AttackSurface 추출
        # ==========================================
        # 문자열 대신 이미 파싱된 soup 객체를 넘깁니다.
        links = link_extractor.extract_links(soup, base_url=page_data.url)

        for link in links:
            if not link.get('params'):
                continue

            method_str = str(link.get('method', 'GET')).upper()
            try:
                method = HttpMethod(method_str)
            except ValueError:
                method = HttpMethod.GET

            link_url = str(link.get('url', ''))

            # 링크 파라미터에도 동적 토큰 정보를 주입합니다.
            parameters = link.get('params', {}).copy()
            if page_data.dynamic_tokens:
                parameters.update(page_data.dynamic_tokens)

            surface = AttackSurface(
                url=link_url,
                method=method,
                param_location=ParamLocation.QUERY,
                parameters=parameters,
                headers=page_data.headers,
                cookies=page_data.cookies,
                source_url=str(page_data.url),
                description=f"Link Parameter (source: {link.get('source', 'unknown')})"
            )
            surfaces.append(surface)

        # ==========================================
        # 3. 중복 검증 및 퍼저 콜백(Callback) 호출
        # ==========================================
        for surface in surfaces:
            if not surface.url:
                continue

            sig = self._generate_signature(surface)
            if sig in self._seen_signatures:
                continue

            self._seen_signatures.add(sig)

            logger.debug(f"[SurfaceBuilder] 퍼저로 공격 표면 전달: {surface.url}")

            # 콜백을 통해 퍼저로 즉시 전송
            result = self.fuzzer_callback(surface)
            if asyncio.iscoroutine(result):
                await result

    def get_stats(self) -> dict:
        return {
            "unique_surfaces_found": len(self._seen_signatures)
        }