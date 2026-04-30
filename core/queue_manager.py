# core/queue_manager.py
import asyncio
from typing import Dict, Any

from core.models import PageData
from utils.logger import get_logger

logger = get_logger(__name__)


class QueueManager:
    """
    비동기 전용 작업 큐 관리자 (asyncio.Queue 기반)

    역할:
    1. Crawler -> Parser: 수집된 PageData를 이벤트 루프 블로킹 없이 안전하게 전달
    """

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size

        # ✨ 비동기 큐 할당 (deque 아님)
        self._page_queue: asyncio.Queue[PageData] = asyncio.Queue(maxsize=max_size)

        # PageData 관련 통계만 유지
        self._stats = {
            'pages_added': 0,
            'pages_processed': 0,
        }

    # ============================================================
    # PageData 관리 (Crawler -> Parser)
    # ============================================================

    async def add_page(self, page: PageData) -> None:
        """[비동기] 크롤러가 수집한 페이지 데이터를 큐에 추가 (append -> put)"""
        await self._page_queue.put(page)
        self._stats['pages_added'] += 1

    async def get_page(self) -> PageData:
        """[비동기] 파서가 처리할 페이지를 큐에서 대기하며 가져옴 (popleft -> get)"""
        page = await self._page_queue.get()
        self._stats['pages_processed'] += 1
        return page

    def has_pages(self) -> bool:
        """처리해야 할 페이지가 남아있는지 확인 (len() -> qsize())"""
        return self._page_queue.qsize() > 0

    # ============================================================
    # 통계 및 관리
    # ============================================================

    def get_stats(self) -> Dict[str, Any]:
        """현재 큐 상태 및 누적 통계 반환 (len() -> qsize())"""
        stats = self._stats.copy()
        stats['pages_pending'] = self._page_queue.qsize()
        return stats

    def clear(self) -> None:
        """큐 초기화 및 통계 리셋 (비동기 큐는 clear가 없으므로 새로 할당)"""
        self._page_queue = asyncio.Queue(maxsize=self.max_size)
        self._stats['pages_added'] = 0
        self._stats['pages_processed'] = 0
        logger.info("QueueManager가 초기화되었습니다.")