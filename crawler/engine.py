# crawler/engine.py

import asyncio
from urllib.parse import urljoin, urlparse
from datetime import datetime
from contextlib import asynccontextmanager
from core.models import (PageData, TokenDetector)
from parser.html_parser import AsyncHTMLParser
from crawler.session_manager import SessionManager
from crawler.url_filter import URLFilter
from utils.logger import get_logger

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
            "dynamic_tokens_found": self.dynamic_tokens_found,
            "duration": self.duration
        }


class CrawlerEngine:
    """개선된 웹 크롤러 엔진"""

    def __init__(self, queue_manager, config=None):
        self.queue_manager = queue_manager
        self.config = config or CrawlConfig()
        self.url_filter = URLFilter()

        # ✨ [핵심 수정] SessionManager 생성 시 url_filter를 주입하여 SSRF 방어벽을 네트워크망에 연결
        self.session_manager = SessionManager(url_filter=self.url_filter)
        self._external_session = False

        self._visited = set()
        self._queue = asyncio.Queue()
        self._stats = CrawlStats()
        self._shutdown = asyncio.Event()

    @staticmethod
    def _get_safe_attr(element, attr_name: str) -> str:
        """bs4 요소에서 속성값을 안전하게 추출"""
        raw_val = element.get(attr_name)
        if isinstance(raw_val, list):
            raw_val = raw_val[0] if raw_val else ""
        return str(raw_val) if raw_val is not None else ""

    def set_session(self, session_manager):
        self.session_manager = session_manager
        # ✨ [핵심 수정] 외부 세션이 주입될 때도 url_filter를 강제로 연결하여 보안 유지
        self.session_manager.url_filter = self.url_filter
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
        while not self._shutdown.is_set():
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                url, depth = item

                if not self._should_continue_crawling():
                    self._shutdown.set()
                    break

                await self._process_url(url, depth)
                await asyncio.sleep(self.config.delay)

            except asyncio.TimeoutError:
                if self._queue.empty(): break
            except Exception as e:
                logger.error("워커 %d 오류: %s", worker_id, e)

    def _should_continue_crawling(self):
        return not self._shutdown.is_set() and self._stats.urls_visited < self.config.max_urls

    async def _process_url(self, url, depth):
        url = self.url_filter.normalize_url(url)
        if url in self._visited or not self.url_filter.should_crawl(url):
            return

        self._visited.add(url)
        self._stats.urls_visited += 1
        logger.info("[%d] %s (depth=%d)", self._stats.urls_visited, url, depth)

        try:
            response = await self._fetch_url(url)
            if response:
                await self._process_response(response, url, depth)
        except Exception as e:
            logger.error("처리 실패 (%s): %s", url, e)
            self._stats.errors += 1

    async def _fetch_url(self, url):
        # session_manager를 통해 안전한 요청 수행 (내부에서 SSRF 검증 진행됨)
        return await self.session_manager.get(url, timeout=self.config.timeout)

    async def _process_response(self, response, url, depth):
        html = response.get("text", "")
        final_url = str(response.get("url", url))
        headers = response.get("headers", {})
        cookies = response.get("cookies", {})

        # ✨ [핵심 수정] CPU를 무겁게 쓰는 HTML 파싱 작업을 이벤트 루프에서 분리 (스레드 풀 실행)
        # 이를 통해 크롤러 워커들이 네트워크 요청을 주고받는 흐름이 멈추지 않도록 보장합니다.
        loop = asyncio.get_running_loop()
        parse_result = await loop.run_in_executor(
            None, AsyncHTMLParser.parse_html_string, html, final_url
        )

        if not parse_result.get("success"):
            logger.warning("파싱 건너뜀 (%s): %s", final_url, parse_result.get("error"))
            return

        soup = parse_result.get("soup")
        if soup is None:
            return

        # 2. PageData 객체 생성 (이미 생성된 soup을 포함하여 중복 파싱 방지)
        page = PageData(
            url=final_url,
            html=html,
            depth=depth,
            headers=headers,
            cookies=cookies,
            soup=soup  # ✨ soup 객체 전달
        )

        # 3. 폼 및 동적 토큰 감지 수행 (기존 로직 유지)
        await self._process_forms_and_tokens(soup, page)

        # 4. 비동기 큐 매니저로 전달 (await 필수)
        await self.queue_manager.add_page(page)

        # 5. 다음 크롤링 대상 URL 추출
        if depth < self.config.max_depth:
            await self._queue_next_urls(soup, final_url, depth)

    async def _process_forms_and_tokens(self, soup, page_data: PageData):
        """이미 파싱된 soup 객체로부터 폼과 토큰을 감지하여 PageData에 저장"""
        for form in soup.find_all("form"):
            self._stats.forms_found += 1
            for input_field in form.find_all(["input", "textarea", "select"]):
                name = input_field.get("name", "").strip()
                if not name: continue

                value = input_field.get("value", "")
                input_type = input_field.get("type", "text")

                if TokenDetector.detect(name, value, input_type):
                    self._stats.dynamic_tokens_found += 1
                    page_data.dynamic_tokens[name] = value

    async def _queue_next_urls(self, soup, base_url: str, depth):
        """soup 객체로부터 다음 URL들을 추출하여 작업 큐에 추가"""
        urls = set()
        # 링크 추출
        for a in soup.find_all("a", href=True):
            full_url = urljoin(base_url, a['href'])
            if self.url_filter.should_crawl(full_url):
                urls.add(full_url)

        # 폼 액션 추출
        for form in soup.find_all("form", action=True):
            full_url = urljoin(base_url, form['action'])
            if self.url_filter.should_crawl(full_url):
                urls.add(full_url)

        for url in urls:
            if url not in self._visited:
                await self._queue.put((url, depth + 1))
                self._stats.urls_queued += 1

    def stop(self):
        self._shutdown.set()

    def get_stats(self):
        return self._stats.to_dict()

    def _log_summary(self):
        logger.info("========== 크롤링 종료 ==========")
        logger.info(
            "방문: %d, 폼: %d, 동적토큰: %d, 시간: %.2f초",
            self._stats.urls_visited, self._stats.forms_found,
            self._stats.dynamic_tokens_found, self._stats.duration
        )