# crawler/engine.py

import asyncio
from urllib.parse import urljoin, urlparse
from datetime import datetime
from bs4 import BeautifulSoup

from core.models import PageData
from utils.logger import get_logger

from .session_manager import SessionManager
from .url_filter import URLFilter

logger = get_logger(__name__)


class CrawlConfig:
    def __init__(self, max_depth=3, max_urls=100, delay=0.5, timeout=10, workers=5):
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.delay = delay
        self.timeout = timeout
        self.workers = workers  # 동시 작업자 수


class CrawlStats:
    def __init__(self):
        self.urls_visited = 0
        self.urls_queued = 0
        self.errors = 0
        self.start_time = datetime.now()

    def get_duration(self):
        return (datetime.now() - self.start_time).total_seconds()

    def to_dict(self):
        return {
            "urls_visited": self.urls_visited,
            "urls_queued": self.urls_queued,
            "errors": self.errors,
            "duration": self.get_duration()
        }


class CrawlerEngine:

    def __init__(self, queue_manager, config=None):
        self.queue_manager = queue_manager
        self.config = config or CrawlConfig()

        self.session_manager = SessionManager()
        self.url_filter = URLFilter()

        self._visited = set()
        self._queue = asyncio.Queue()
        self._stats = CrawlStats()
        self._running = False

    async def start(self, start_url):
        """크롤링 시작"""
        logger.info("========== 크롤링 시작 ==========")
        logger.info("대상: %s", start_url)

        self._visited.clear()
        self._stats = CrawlStats()
        self._running = True

        # 도메인 제한
        domain = urlparse(start_url).netloc
        self.url_filter.add_allowed_domain(domain)

        # 시작 URL 추가
        await self._queue.put((start_url, 0))
        self._stats.urls_queued = 1

        # 세션 생성
        await self.session_manager.create_session()

        try:
            # 워커 생성
            workers = []
            for _ in range(self.config.workers):
                task = asyncio.create_task(self._worker())
                workers.append(task)

            # 모든 워커 완료 대기
            await asyncio.gather(*workers)

        finally:
            await self.session_manager.close()
            self._running = False

        logger.info("========== 크롤링 종료 ==========")
        logger.info("방문: %d, 에러: %d, 시간: %.2f초",
                   self._stats.urls_visited,
                   self._stats.errors,
                   self._stats.get_duration())

        return self._stats

    async def _worker(self):
        """크롤링 워커"""
        while self._running:
            try:
                # 타임아웃으로 URL 가져오기
                url, depth = await asyncio.wait_for(
                    self._queue.get(),
                    timeout=3.0
                )
            except asyncio.TimeoutError:
                # 큐가 비면 종료
                break

            # 최대 URL 수 체크
            if self._stats.urls_visited >= self.config.max_urls:
                break

            # URL 처리
            await self._process(url, depth)

            # 딜레이
            await asyncio.sleep(self.config.delay)

    async def _process(self, url, depth):
        """단일 URL 처리"""
        # 정규화
        url = self.url_filter.normalize_url(url)

        # 중복 체크
        if url in self._visited:
            return

        # 필터 체크
        if not self.url_filter.should_crawl(url):
            return

        # 방문 기록
        self._visited.add(url)
        self._stats.urls_visited += 1

        logger.info("[%d] %s (depth=%d)", self._stats.urls_visited, url, depth)

        try:
            # HTTP 요청
            response = await self.session_manager.get(url, timeout=self.config.timeout)

            if response is None:
                self._stats.errors += 1
                return

            html = response.get("text", "")
            final_url = response.get("url", url)

            # Parser로 넘김 (PageData)
            page = PageData(
                url=final_url,
                html=html,
                depth=depth
            )
            self.queue_manager.add_page(page)

            # 링크 추출 및 큐 추가
            if depth < self.config.max_depth:
                links = self._extract_links(html, final_url)
                for link in links:
                    if link not in self._visited:
                        await self._queue.put((link, depth + 1))
                        self._stats.urls_queued += 1

        except Exception as e:
            logger.error("처리 실패 (%s): %s", url, e)
            self._stats.errors += 1

    def _extract_links(self, html, base_url):
        """간단한 링크 추출"""
        links = []

        try:
            soup = BeautifulSoup(html, "html.parser")

            for a in soup.find_all("a", href=True):
                href = a["href"]

                # 빈 링크, 앵커, JS 제외
                if not href or href.startswith(("#", "javascript:", "mailto:")):
                    continue

                # 절대 URL로 변환
                full_url = urljoin(base_url, href)

                # 필터 통과 시 추가
                if self.url_filter.should_crawl(full_url):
                    links.append(full_url)

        except Exception as e:
            logger.warning("링크 추출 실패: %s", e)

        return links

    def stop(self):
        """크롤링 중지"""
        self._running = False
        logger.info("크롤링 중지 요청")

    def get_stats(self):
        """통계 반환"""
        return self._stats.to_dict()