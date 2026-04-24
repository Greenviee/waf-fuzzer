# crawler/engine.py

import asyncio
import re
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
from bs4 import BeautifulSoup
from contextlib import asynccontextmanager
import json

from core.models import (
    PageData,
    AttackSurface,
    HttpMethod,
    ParamLocation,
    TokenDetector
)
from utils.logger import get_logger

from .session_manager import SessionManager
from .url_filter import URLFilter

logger = get_logger(__name__)


class CrawlConfig:
    """크롤링 설정 클래스"""

    def __init__(self, max_depth=3, max_urls=100, delay=0.5, timeout=10, workers=5):
        """
        크롤링 설정 초기화

        Args:
            max_depth: 최대 크롤링 깊이
            max_urls: 최대 크롤링 URL 수
            delay: 요청 간 지연 시간(초)
            timeout: 요청 타임아웃(초)
            workers: 동시 작업자 수
        """
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.delay = delay
        self.timeout = timeout
        self.workers = workers


class CrawlStats:
    """크롤링 통계 클래스"""

    def __init__(self):
        """통계 초기화"""
        self.urls_visited = 0
        self.urls_queued = 0
        self.errors = 0
        self.forms_found = 0
        self.apis_found = 0
        self.attack_surfaces = 0
        self.dynamic_tokens_found = 0
        self.start_time = datetime.now()

    @property
    def duration(self):
        """크롤링 경과 시간"""
        return (datetime.now() - self.start_time).total_seconds()

    def to_dict(self):
        """통계를 딕셔너리로 변환"""
        return {
            "urls_visited": self.urls_visited,
            "urls_queued": self.urls_queued,
            "errors": self.errors,
            "forms_found": self.forms_found,
            "apis_found": self.apis_found,
            "attack_surfaces": self.attack_surfaces,
            "dynamic_tokens_found": self.dynamic_tokens_found,
            "duration": self.duration
        }


class CrawlerEngine:
    """웹 크롤러 엔진"""

    def __init__(self, queue_manager, config=None):
        """
        크롤러 엔진 초기화

        Args:
            queue_manager: 큐 관리자 인스턴스
            config: CrawlConfig 인스턴스 (기본값: None)
        """
        self.queue_manager = queue_manager
        self.config = config or CrawlConfig()

        self.session_manager = SessionManager()
        self.url_filter = URLFilter()

        self._visited = set()
        self._queue = asyncio.Queue()
        self._stats = CrawlStats()
        self._workers = []
        self._shutdown = asyncio.Event()
        self._external_session = False

        # 발견된 API 패턴 추적
        self._api_patterns = {
            'json': ['/api/', '/v1/', '/v2/', '/graphql'],
            'rest': ['PUT', 'DELETE', 'PATCH']
        }

        # 공격 가능한 헤더 목록
        self._injectable_headers = [
            "User-Agent",
            "Referer",
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Originating-IP",
            "X-Remote-IP",
            "X-Remote-Addr",
            "X-Client-IP",
            "Accept-Language",
            "Accept-Encoding",
            "Origin",
            "Host",
        ]

    def set_session(self, session_manager):
        """
        외부 세션 주입 (로그인된 세션 사용)

        Args:
            session_manager: 이미 로그인된 SessionManager 인스턴스
        """
        self.session_manager = session_manager
        self._external_session = True
        logger.info("외부 세션 연결됨")

    @asynccontextmanager
    async def _session_context(self):
        """세션 컨텍스트 관리"""
        if not self._external_session:
            await self.session_manager.create_session()
        try:
            yield
        finally:
            if not self._external_session:
                await self.session_manager.close()

    async def start(self, start_url):
        """
        크롤링 시작

        Args:
            start_url: 시작 URL

        Returns:
            CrawlStats: 크롤링 통계
        """
        logger.info("========== 크롤링 시작 ==========")
        logger.info("대상: %s", start_url)

        self._reset_state()
        self._setup_domain_filter(start_url)

        await self._queue.put((start_url, 0))
        self._stats.urls_queued = 1

        async with self._session_context():
            await self._run_workers()

        self._log_summary()
        return self._stats

    def _reset_state(self):
        """상태 초기화"""
        self._visited.clear()
        self._stats = CrawlStats()
        self._shutdown.clear()

    def _setup_domain_filter(self, start_url):
        """도메인 필터 설정"""
        domain = urlparse(start_url).netloc
        self.url_filter.add_allowed_domain(domain)

    async def _run_workers(self):
        """워커 실행 및 관리"""
        self._workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self.config.workers)
        ]

        try:
            await asyncio.gather(*self._workers, return_exceptions=True)
        except Exception as e:
            logger.error("워커 실행 중 오류: %s", e)
        finally:
            await self._cleanup_workers()

    async def _cleanup_workers(self):
        """워커 정리"""
        self._shutdown.set()

        for _ in self._workers:
            await self._queue.put((None, None))

        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def _worker(self, worker_id):
        """크롤링 워커"""
        logger.debug("워커 %d 시작", worker_id)

        while not self._shutdown.is_set():
            try:
                item = await asyncio.wait_for(
                    self._queue.get(),
                    timeout=3.0
                )

                if item[0] is None:
                    break

                url, depth = item

                if self._should_continue_crawling():
                    await self._process_url(url, depth)
                    await asyncio.sleep(self.config.delay)

            except asyncio.TimeoutError:
                if self._queue.empty() and not self._shutdown.is_set():
                    break
            except Exception as e:
                logger.error("워커 %d 오류: %s", worker_id, e)

        logger.debug("워커 %d 종료", worker_id)

    def _should_continue_crawling(self):
        """크롤링 계속 여부 확인"""
        return (
            not self._shutdown.is_set() and
            self._stats.urls_visited < self.config.max_urls
        )

    async def _process_url(self, url, depth):
        """URL 처리"""
        url = self.url_filter.normalize_url(url)

        if not self._is_valid_url(url):
            return

        self._mark_visited(url)
        logger.info("[%d] %s (depth=%d)", self._stats.urls_visited, url, depth)

        try:
            response = await self._fetch_url(url)
            if not response:
                return

            await self._process_response(response, url, depth)

        except Exception as e:
            logger.error("처리 실패 (%s): %s", url, e)
            self._stats.errors += 1

    def _is_valid_url(self, url):
        """URL 유효성 검사"""
        return (
            url not in self._visited and
            self.url_filter.should_crawl(url)
        )

    def _mark_visited(self, url):
        """URL 방문 표시"""
        self._visited.add(url)
        self._stats.urls_visited += 1

    async def _fetch_url(self, url):
        """URL 가져오기"""
        response = await self.session_manager.get(url, timeout=self.config.timeout)

        if not response:
            self._stats.errors += 1
            return None

        final_url = response.get("url", url)
        if self._is_login_redirect(url, final_url):
            logger.warning("로그인 페이지로 리다이렉트됨: %s", final_url)
            self._stats.errors += 1
            return None

        return response

    @staticmethod
    def _is_login_redirect(original_url, final_url):
        """로그인 리다이렉트 여부 확인"""
        return (
            "login" in final_url.lower() and
            "login" not in original_url.lower()
        )

    async def _process_response(self, response, url, depth):
        """응답 처리"""
        html = response.get("text", "")
        final_url = response.get("url", url)
        headers = response.get("headers", {})
        cookies = response.get("cookies", {})

        # 페이지 데이터 저장
        page = PageData(
            url=final_url,
            html=html,
            depth=depth
        )
        self.queue_manager.add_page(page)

        # 공격 표면 추출 (모든 유형)
        await self._extract_attack_surfaces(html, final_url, headers, cookies)

        # 다음 깊이 크롤링
        if depth < self.config.max_depth:
            await self._queue_next_urls(html, final_url, depth)

    async def _extract_attack_surfaces(self, html, base_url, headers, cookies):
        """
        공격 표면 추출 (모든 유형)

        Args:
            html: HTML 콘텐츠
            base_url: 베이스 URL
            headers: 응답 헤더
            cookies: 응답 쿠키
        """
        try:
            soup = BeautifulSoup(html, "html.parser")

            # 1. 폼 기반 공격 표면 (BODY_FORM, BODY_JSON)
            await self._extract_forms_surfaces(soup, base_url)

            # 2. AJAX/API 엔드포인트 (BODY_JSON)
            await self._extract_api_surfaces(html, base_url, headers)

            # 3. URL 쿼리 파라미터 (QUERY)
            await self._extract_query_surfaces(soup, base_url)

            # 4. 헤더 기반 공격 표면 (HEADER)
            await self._extract_header_surfaces(base_url)

            # 5. 쿠키 기반 공격 표면 (COOKIE)
            await self._extract_cookie_surfaces(base_url, cookies)

        except Exception as e:
            logger.warning("공격 표면 추출 실패: %s", e)

    async def _extract_forms_surfaces(self, soup, base_url):
        """
        폼 기반 공격 표면 추출 (동적 토큰 감지 포함)

        Args:
            soup: BeautifulSoup 객체
            base_url: 베이스 URL
        """
        for form in soup.find_all("form"):
            self._stats.forms_found += 1

            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            enctype = form.get("enctype", "application/x-www-form-urlencoded")

            form_url = urljoin(base_url, action) if action else base_url

            # 파라미터 및 동적 토큰 추출
            parameters = {}
            dynamic_tokens = []

            for input_field in form.find_all(["input", "textarea", "select"]):
                name = input_field.get("name")
                if not name:
                    continue

                value = input_field.get("value", "")
                input_type = input_field.get("type", "text")

                # 동적 토큰 감지
                if TokenDetector.detect(name, value, input_type):
                    dynamic_tokens.append(name)
                    self._stats.dynamic_tokens_found += 1
                    logger.debug(
                        "동적 토큰 감지: %s (값: %s...)",
                        name,
                        value[:20] if value else ""
                    )

                # hidden 필드는 값 유지, 나머지는 빈 값
                if input_type != "hidden":
                    value = ""

                parameters[name] = value

            if parameters:
                # 파라미터 위치 결정
                if method == "GET":
                    param_location = ParamLocation.QUERY
                elif "json" in enctype.lower():
                    param_location = ParamLocation.BODY_JSON
                else:
                    param_location = ParamLocation.BODY_FORM

                # HTTP 메서드 결정
                try:
                    http_method = HttpMethod[method]
                except KeyError:
                    http_method = HttpMethod.POST

                surface = AttackSurface(
                    url=form_url,
                    method=http_method,
                    param_location=param_location,
                    parameters=parameters,
                    dynamic_tokens=dynamic_tokens,
                    source_url=base_url,
                    description=f"Form [{method}] from {base_url}"
                )

                self.queue_manager.add_attack_surface(surface)
                self._stats.attack_surfaces += 1

                if dynamic_tokens:
                    logger.info(
                        "폼 공격 표면 추가: %s (동적 토큰: %s)",
                        form_url,
                        dynamic_tokens
                    )
                else:
                    logger.debug(
                        "폼 공격 표면 추가: %s (%s)",
                        form_url,
                        param_location.value
                    )

    async def _extract_api_surfaces(self, html, base_url, headers):
        """
        AJAX/API 엔드포인트 추출 (BODY_JSON)

        Args:
            html: HTML 콘텐츠
            base_url: 베이스 URL
            headers: 응답 헤더
        """
        # JSON 응답 감지
        content_type = headers.get("content-type", "").lower()
        if "application/json" in content_type:
            self._stats.apis_found += 1

            try:
                json_data = json.loads(html)
                parameters = self._extract_json_parameters(json_data)

                if parameters:
                    surface = AttackSurface(
                        url=base_url,
                        method=HttpMethod.POST,
                        param_location=ParamLocation.BODY_JSON,
                        parameters=parameters,
                        dynamic_tokens=[],
                        source_url=base_url,
                        description="JSON API endpoint"
                    )

                    self.queue_manager.add_attack_surface(surface)
                    self._stats.attack_surfaces += 1
                    logger.debug("JSON API 공격 표면 추가: %s", base_url)

            except json.JSONDecodeError:
                pass

        # JavaScript 내 API 호출 패턴 찾기
        api_patterns = [
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            r'\$\.(get|post)\s*\(\s*["\']([^"\']+)["\']',
        ]

        for pattern in api_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                # 튜플인 경우 URL 부분 추출
                if isinstance(match, tuple):
                    api_path = match[-1]
                    method_hint = match[0] if len(match) > 1 else "GET"
                else:
                    api_path = match
                    method_hint = "GET"

                api_url = urljoin(base_url, api_path)

                # 이미 처리된 URL 스킵
                if not self.url_filter.should_crawl(api_url):
                    continue

                # HTTP 메서드 결정
                method_map = {
                    "get": HttpMethod.GET,
                    "post": HttpMethod.POST,
                    "put": HttpMethod.PUT,
                    "delete": HttpMethod.DELETE,
                }
                http_method = method_map.get(method_hint.lower(), HttpMethod.GET)

                self._stats.apis_found += 1

                surface = AttackSurface(
                    url=api_url,
                    method=http_method,
                    param_location=ParamLocation.BODY_JSON,
                    parameters={},
                    dynamic_tokens=[],
                    source_url=base_url,
                    description=f"API endpoint found in JavaScript [{http_method.value}]"
                )

                self.queue_manager.add_attack_surface(surface)
                self._stats.attack_surfaces += 1
                logger.debug("JS API 공격 표면 추가: %s", api_url)

    async def _extract_query_surfaces(self, soup, base_url):
        """
        URL 쿼리 파라미터 추출 (QUERY)

        Args:
            soup: BeautifulSoup 객체
            base_url: 베이스 URL
        """
        # 현재 URL의 쿼리 파라미터
        parsed = urlparse(base_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            if params:
                parameters = {k: v[0] if v else "" for k, v in params.items()}

                surface = AttackSurface(
                    url=base_url.split('?')[0],
                    method=HttpMethod.GET,
                    param_location=ParamLocation.QUERY,
                    parameters=parameters,
                    dynamic_tokens=[],
                    source_url=base_url,
                    description="Current URL query parameters"
                )

                self.queue_manager.add_attack_surface(surface)
                self._stats.attack_surfaces += 1

        # 페이지 내 링크의 쿼리 파라미터
        processed_urls = set()
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if "?" not in href:
                continue

            full_url = urljoin(base_url, href)

            # 중복 방지
            url_without_query = full_url.split('?')[0]
            if url_without_query in processed_urls:
                continue
            processed_urls.add(url_without_query)

            if not self.url_filter.should_crawl(full_url):
                continue

            parsed = urlparse(full_url)
            params = parse_qs(parsed.query)

            if params:
                parameters = {k: v[0] if v else "" for k, v in params.items()}

                surface = AttackSurface(
                    url=url_without_query,
                    method=HttpMethod.GET,
                    param_location=ParamLocation.QUERY,
                    parameters=parameters,
                    dynamic_tokens=[],
                    source_url=base_url,
                    description="Link with query parameters"
                )

                self.queue_manager.add_attack_surface(surface)
                self._stats.attack_surfaces += 1
                logger.debug("쿼리 공격 표면 추가: %s", url_without_query)

    async def _extract_header_surfaces(self, base_url):
        """
        헤더 기반 공격 표면 추출 (HEADER)

        Args:
            base_url: 베이스 URL
        """
        # 공격 가능한 헤더들을 파라미터로 구성
        header_parameters = {}
        for header_name in self._injectable_headers:
            header_parameters[header_name] = ""

        surface = AttackSurface(
            url=base_url,
            method=HttpMethod.GET,
            param_location=ParamLocation.HEADER,
            parameters=header_parameters,
            dynamic_tokens=[],
            source_url=base_url,
            description="HTTP Header injection points"
        )

        self.queue_manager.add_attack_surface(surface)
        self._stats.attack_surfaces += 1
        logger.debug(
            "헤더 공격 표면 추가: %s (%d개 헤더)",
            base_url,
            len(header_parameters)
        )

    async def _extract_cookie_surfaces(self, base_url, cookies):
        """
        쿠키 기반 공격 표면 추출 (COOKIE)

        Args:
            base_url: 베이스 URL
            cookies: 응답에서 받은 쿠키 또는 세션의 쿠키
        """
        # 응답 쿠키가 없으면 세션 매니저에서 가져오기
        cookie_dict = cookies if cookies else {}

        if not cookie_dict:
            try:
                cookie_dict = self.session_manager.get_cookies()
            except Exception:
                cookie_dict = {}

        if not cookie_dict:
            logger.debug("쿠키 없음, 쿠키 공격 표면 스킵: %s", base_url)
            return

        # 쿠키를 파라미터로 변환
        cookie_parameters = {name: value for name, value in cookie_dict.items()}

        surface = AttackSurface(
            url=base_url,
            method=HttpMethod.GET,
            param_location=ParamLocation.COOKIE,
            parameters=cookie_parameters,
            cookies=cookie_parameters,
            dynamic_tokens=[],
            source_url=base_url,
            description=f"Cookie injection points ({len(cookie_parameters)} cookies)"
        )

        self.queue_manager.add_attack_surface(surface)
        self._stats.attack_surfaces += 1
        logger.debug(
            "쿠키 공격 표면 추가: %s (%d개 쿠키)",
            base_url,
            len(cookie_parameters)
        )

    def _extract_json_parameters(self, json_data, prefix=""):
        """
        JSON 구조에서 파라미터 추출 (재귀적)

        Args:
            json_data: JSON 데이터
            prefix: 키 프리픽스

        Returns:
            dict: 추출된 파라미터
        """
        parameters = {}

        if isinstance(json_data, dict):
            for key, value in json_data.items():
                full_key = f"{prefix}.{key}" if prefix else key

                if isinstance(value, (dict, list)):
                    nested = self._extract_json_parameters(value, full_key)
                    parameters.update(nested)
                else:
                    parameters[full_key] = ""

        elif isinstance(json_data, list) and json_data:
            if isinstance(json_data[0], dict):
                nested = self._extract_json_parameters(json_data[0], f"{prefix}[0]")
                parameters.update(nested)

        return parameters

    async def _queue_next_urls(self, html, base_url, depth):
        """다음 URL들을 큐에 추가"""
        extracted_data = self._extract_urls(html, base_url)

        for url in extracted_data["urls"]:
            if url not in self._visited:
                await self._queue.put((url, depth + 1))
                self._stats.urls_queued += 1

    def _extract_urls(self, html, base_url):
        """URL 추출 (링크 + 폼 액션)"""
        urls = set()

        try:
            soup = BeautifulSoup(html, "html.parser")
            urls.update(self._extract_links(soup, base_url))
            urls.update(self._extract_form_actions(soup, base_url))

        except Exception as e:
            logger.warning("URL 추출 실패: %s", e)

        return {"urls": list(urls)}

    def _extract_links(self, soup, base_url):
        """링크 추출"""
        links = set()

        for element in soup.find_all("a", href=True):
            url = self._process_extracted_url(element["href"], base_url)
            if url:
                links.add(url)

        return links

    def _extract_form_actions(self, soup, base_url):
        """폼 액션 URL 추출"""
        actions = set()

        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action:
                url = self._process_extracted_url(action, base_url)
                if url:
                    actions.add(url)

        return actions

    def _process_extracted_url(self, url, base_url):
        """추출된 URL 처리"""
        if not url or url.startswith(("#", "javascript:", "mailto:")):
            return None

        full_url = urljoin(base_url, url)

        if self.url_filter.should_crawl(full_url):
            return full_url

        return None

    def stop(self):
        """크롤링 중지"""
        logger.info("크롤링 중지 요청")
        self._shutdown.set()

    def get_stats(self):
        """통계 반환"""
        return self._stats.to_dict()

    def _log_summary(self):
        """크롤링 요약 로그 출력"""
        logger.info("========== 크롤링 종료 ==========")
        logger.info(
            "방문: %d, 에러: %d, 폼: %d, API: %d, 공격표면: %d, 동적토큰: %d, 시간: %.2f초",
            self._stats.urls_visited,
            self._stats.errors,
            self._stats.forms_found,
            self._stats.apis_found,
            self._stats.attack_surfaces,
            self._stats.dynamic_tokens_found,
            self._stats.duration
        )
