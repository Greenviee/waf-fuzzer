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

from crawler.session_manager import SessionManager
from crawler.url_filter import URLFilter

logger = get_logger(__name__)


class CrawlConfig:
    """크롤링 설정 클래스"""

    def __init__(self, max_depth=3, max_urls=100, delay=0.5, timeout=10, workers=5):
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.delay = delay
        self.timeout = timeout
        self.workers = workers


class CrawlStats:
    """크롤링 통계 클래스"""

    def __init__(self):
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
        return (datetime.now() - self.start_time).total_seconds()

    def to_dict(self):
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
        self._seen_surfaces = set()

        self._api_patterns = {
            'json': ['/api/', '/v1/', '/v2/', '/graphql'],
            'rest': ['PUT', 'DELETE', 'PATCH']
        }

        self._injectable_headers = [
            "User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP",
            "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr", "X-Client-IP",
            "Accept-Language", "Accept-Encoding", "Origin", "Host",
        ]

    @staticmethod
    def _get_safe_attr(element, attr_name: str) -> str:
        """
        bs4 요소에서 속성값을 안전하게 문자열로 추출
        ✨ [수정] PyCharm의 str | bytes 경고를 해결하고 실제 바이트 디코딩 처리
        """
        raw_val = element.get(attr_name)

        # 1. 리스트인 경우 첫 번째 요소 추출 (class 속성 등)
        if isinstance(raw_val, list):
            raw_val = raw_val[0] if raw_val else ""

        # 2. 파이참 경고 해결: bytes 타입일 경우 디코딩
        if isinstance(raw_val, bytes):
            return raw_val.decode('utf-8', errors='ignore')

        # 3. 그 외 (문자열 등)
        if raw_val is not None:
            return str(raw_val)

        return ""

    def set_session(self, session_manager):
        self.session_manager = session_manager
        self._external_session = True
        logger.info("외부 세션 연결됨")

    @asynccontextmanager
    async def _session_context(self):
        if not self._external_session:
            await self.session_manager.create_session()
        try:
            yield
        finally:
            if not self._external_session:
                await self.session_manager.close()

    async def start(self, start_url):
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
        self._visited.clear()
        self._seen_surfaces.clear()
        self._stats = CrawlStats()
        self._shutdown.clear()

    def _setup_domain_filter(self, start_url):
        domain = urlparse(start_url).netloc
        self.url_filter.add_allowed_domain(domain)

    async def _run_workers(self):
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
        self._shutdown.set()

        for worker in self._workers:
            if not worker.done():
                worker.cancel()

        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)

        self._workers.clear()

    async def _worker(self, worker_id):
        logger.debug("워커 %d 시작", worker_id)

        while not self._shutdown.is_set():
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=1.0)

                if item[0] is None:
                    break

                url, depth = item

                if not self._should_continue_crawling():
                    self._shutdown.set()
                    break

                await self._process_url(url, depth)
                await asyncio.sleep(self.config.delay)

            except asyncio.TimeoutError:
                if self._queue.empty() and not self._shutdown.is_set():
                    break
            except asyncio.CancelledError:
                logger.debug("워커 %d 강제 취소됨", worker_id)
                break
            # noinspection PyBroadException
            except Exception as e:
                logger.error("워커 %d 오류: %s", worker_id, e)

        logger.debug("워커 %d 종료", worker_id)

    def _should_continue_crawling(self):
        return (
                not self._shutdown.is_set() and
                self._stats.urls_visited < self.config.max_urls
        )

    async def _process_url(self, url, depth):
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

        # noinspection PyBroadException
        except Exception as e:
            logger.error("처리 실패 (%s): %s", url, e)
            self._stats.errors += 1

    def _is_valid_url(self, url):
        return url not in self._visited and self.url_filter.should_crawl(url)

    def _mark_visited(self, url):
        self._visited.add(url)
        self._stats.urls_visited += 1

    async def _fetch_url(self, url, max_retries=2):
        for attempt in range(max_retries):
            try:
                response = await self.session_manager.get(url, timeout=self.config.timeout)

                if not response:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1.0)
                        continue
                    self._stats.errors += 1
                    return None

                final_url = str(response.get("url", url))
                if self._is_login_redirect(str(url), final_url):
                    logger.warning("로그인 페이지로 리다이렉트됨: %s", final_url)
                    self._stats.errors += 1
                    return None

                return response

            # noinspection PyBroadException
            except Exception as e:
                logger.debug("요청 실패 (%s) 시도 %d/%d: %s", url, attempt + 1, max_retries, e)
                if attempt < max_retries - 1:
                    await asyncio.sleep(1.0)
                else:
                    self._stats.errors += 1
                    return None
        return None

    @staticmethod
    def _is_login_redirect(original_url: str, final_url: str) -> bool:
        return "login" in final_url.lower() and "login" not in original_url.lower()

    async def _process_response(self, response, url, depth):
        html = response.get("text", "")
        final_url = str(response.get("url", url))
        headers = response.get("headers", {})
        cookies = response.get("cookies", {})

        page = PageData(url=final_url, html=html, depth=depth)
        self.queue_manager.add_page(page)

        await self._extract_attack_surfaces(html, final_url, headers, cookies)

        if depth < self.config.max_depth:
            await self._queue_next_urls(html, final_url, depth)

    def _add_unique_attack_surface(self, surface: AttackSurface) -> bool:
        param_keys = tuple(sorted(surface.parameters.keys()))
        surface_hash = hash((str(surface.url), surface.method.value, param_keys))

        if surface_hash not in self._seen_surfaces:
            self._seen_surfaces.add(surface_hash)
            self.queue_manager.add_attack_surface(surface)
            self._stats.attack_surfaces += 1
            return True

        return False

    async def _extract_attack_surfaces(self, html, base_url, headers, cookies):
        try:
            soup = BeautifulSoup(html, "html.parser")
            base_url_str = str(base_url)

            await self._extract_forms_surfaces(soup, base_url_str)
            await self._extract_api_surfaces(html, base_url_str, headers)
            await self._extract_query_surfaces(soup, base_url_str)
            await self._extract_header_surfaces(base_url_str)
            await self._extract_cookie_surfaces(base_url_str, cookies)
        # noinspection PyBroadException
        except Exception as e:
            logger.warning("공격 표면 추출 실패: %s", e)

    async def _extract_forms_surfaces(self, soup, base_url: str):
        for form in soup.find_all("form"):
            self._stats.forms_found += 1

            action = self._get_safe_attr(form, "action")
            # ✨ [수정] Any | None 경고 해결 (명시적 str 캐스팅)
            method = str(self._get_safe_attr(form, "method") or "GET").upper()
            enctype = str(self._get_safe_attr(form, "enctype") or "application/x-www-form-urlencoded")

            form_url = urljoin(base_url, action) if action else base_url

            parameters = {}
            dynamic_tokens = []

            for input_field in form.find_all(["input", "textarea", "select"]):
                name = self._get_safe_attr(input_field, "name")
                if not name:
                    continue

                value = self._get_safe_attr(input_field, "value")
                input_type = str(self._get_safe_attr(input_field, "type") or "text")

                if TokenDetector.detect(name, value, input_type):
                    dynamic_tokens.append(name)
                    self._stats.dynamic_tokens_found += 1
                    logger.info("🔑 동적 토큰 감지: name=%s, type=%s", name, input_type)

                if input_type != "hidden":
                    value = ""

                parameters[name] = value

            if parameters:
                if method == "GET":
                    param_location = ParamLocation.QUERY
                elif "json" in enctype.lower():  # ✨ Any|None 경고 해결됨
                    param_location = ParamLocation.BODY_JSON
                else:
                    param_location = ParamLocation.BODY_FORM

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

                if self._add_unique_attack_surface(surface):
                    if dynamic_tokens:
                        logger.info("폼 공격 표면 추가: %s (동적 토큰: %s)", form_url, dynamic_tokens)
                    else:
                        logger.debug("폼 공격 표면 추가: %s (%s)", form_url, param_location.value)

    async def _extract_api_surfaces(self, html, base_url: str, headers):
        raw_ct = headers.get("content-type")
        content_type = str(raw_ct).lower() if raw_ct else ""

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

                    if self._add_unique_attack_surface(surface):
                        logger.debug("JSON API 공격 표면 추가: %s", base_url)

            except json.JSONDecodeError:
                pass

        api_patterns = [
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            r'\$\.(get|post)\s*\(\s*["\']([^"\']+)["\']',
        ]

        for pattern in api_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    api_path = str(match[-1])
                    method_hint = str(match[0]) if len(match) > 1 else "GET"
                else:
                    api_path = str(match)
                    method_hint = "GET"

                api_url = urljoin(base_url, api_path)

                if not self.url_filter.should_crawl(api_url):
                    continue

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

                if self._add_unique_attack_surface(surface):
                    logger.debug("JS API 공격 표면 추가: %s", api_url)

    async def _extract_query_surfaces(self, soup, base_url: str):
        parsed = urlparse(base_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            if params:
                parameters = {str(k): str(v[0]) if v else "" for k, v in params.items()}
                surface = AttackSurface(
                    url=base_url.split('?')[0],
                    method=HttpMethod.GET,
                    param_location=ParamLocation.QUERY,
                    parameters=parameters,
                    dynamic_tokens=[],
                    source_url=base_url,
                    description="Current URL query parameters"
                )
                self._add_unique_attack_surface(surface)

        processed_urls = set()
        for link in soup.find_all("a", href=True):
            href = self._get_safe_attr(link, "href")

            if not href or "?" not in href:
                continue

            # ✨ [수정] bytes 경고 해결 및 안전한 결합
            full_url = urljoin(base_url, href)
            url_without_query = full_url.split('?')[0]

            if url_without_query in processed_urls:
                continue

            processed_urls.add(url_without_query)

            if not self.url_filter.should_crawl(full_url):
                continue

            parsed = urlparse(full_url)
            params = parse_qs(parsed.query)

            if params:
                parameters = {str(k): str(v[0]) if v else "" for k, v in params.items()}
                surface = AttackSurface(
                    url=url_without_query,
                    method=HttpMethod.GET,
                    param_location=ParamLocation.QUERY,
                    parameters=parameters,
                    dynamic_tokens=[],
                    source_url=base_url,
                    description="Link with query parameters"
                )

                if self._add_unique_attack_surface(surface):
                    logger.debug("쿼리 공격 표면 추가: %s", url_without_query)

    async def _extract_header_surfaces(self, base_url: str):
        header_parameters = {name: "" for name in self._injectable_headers}
        surface = AttackSurface(
            url=base_url,
            method=HttpMethod.GET,
            param_location=ParamLocation.HEADER,
            parameters=header_parameters,
            dynamic_tokens=[],
            source_url=base_url,
            description="HTTP Header injection points"
        )
        if self._add_unique_attack_surface(surface):
            logger.debug("헤더 공격 표면 추가: %s (%d개 헤더)", base_url, len(header_parameters))

    async def _extract_cookie_surfaces(self, base_url: str, cookies):
        cookie_dict = cookies if cookies else {}

        if not cookie_dict:
            # noinspection PyBroadException
            try:
                cookie_dict = self.session_manager.get_cookies()
            except Exception:
                cookie_dict = {}

        if not cookie_dict:
            return

        cookie_parameters = {str(name): str(value) for name, value in cookie_dict.items()}

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

        if self._add_unique_attack_surface(surface):
            logger.debug("쿠키 공격 표면 추가: %s (%d개 쿠키)", base_url, len(cookie_parameters))

    def _extract_json_parameters(self, json_data, prefix=""):
        parameters = {}

        if isinstance(json_data, dict):
            for key, value in json_data.items():
                full_key = f"{prefix}.{key}" if prefix else str(key)
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

    async def _queue_next_urls(self, html, base_url: str, depth):
        extracted_data = self._extract_urls(html, base_url)
        for url in extracted_data["urls"]:
            if url not in self._visited:
                await self._queue.put((url, depth + 1))
                self._stats.urls_queued += 1

    def _extract_urls(self, html, base_url: str):
        urls = set()
        try:
            soup = BeautifulSoup(html, "html.parser")
            urls.update(self._extract_links(soup, base_url))
            urls.update(self._extract_form_actions(soup, base_url))
        # noinspection PyBroadException
        except Exception as e:
            logger.warning("URL 추출 실패: %s", e)
        return {"urls": list(urls)}

    def _extract_links(self, soup, base_url: str):
        links = set()
        for element in soup.find_all("a", href=True):
            href = self._get_safe_attr(element, "href")
            url = self._process_extracted_url(href, base_url)
            if url:
                links.add(url)
        return links

    def _extract_form_actions(self, soup, base_url: str):
        actions = set()
        for form in soup.find_all("form"):
            action = self._get_safe_attr(form, "action")
            if action:
                url = self._process_extracted_url(action, base_url)
                if url:
                    actions.add(url)
        return actions

    def _process_extracted_url(self, url: str, base_url: str) -> str | None:
        if not url or url.startswith(("#", "javascript:", "mailto:")):
            return None

        # ✨ [수정] url, base_url이 명확히 문자열로 타입 체킹됨
        full_url = urljoin(base_url, url)
        if self.url_filter.should_crawl(full_url):
            return full_url
        return None

    def stop(self):
        logger.info("크롤링 중지 요청")
        self._shutdown.set()

    def get_stats(self):
        return self._stats.to_dict()

    def _log_summary(self):
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