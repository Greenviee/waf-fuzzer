# core/queue_manager.py
"""
큐 관리자
크롤러 → 파서 → 퍼저 간의 데이터 전달을 관리

담당: Team A 공통
"""

import threading
from collections import deque

from utils.logger import get_logger

logger = get_logger(__name__)


class QueueManager:
    """
    작업 큐 관리자

    역할:
    1. 크롤러 → 파서: CrawlResult 전달
    2. 파서 → 퍼저: AttackSurface 전달
    """

    def __init__(self, max_size=10000):
        self.max_size = max_size
        self._crawl_results = deque(maxlen=max_size)
        self._attack_surfaces = deque(maxlen=max_size)
        self._seen_surface_ids = set()
        self._lock = threading.Lock()
        self._stats = {
            'crawl_results_added': 0,
            'crawl_results_processed': 0,
            'surfaces_added': 0,
            'surfaces_processed': 0,
            'duplicates_skipped': 0,
        }

    # ============================================================
    # 크롤러 → 파서 (CrawlResult)
    # ============================================================

    def add_crawl_result(self, result):
        """크롤러가 수집한 결과를 큐에 추가"""
        self._lock.acquire()
        try:
            self._crawl_results.append(result)
            self._stats['crawl_results_added'] += 1
        finally:
            self._lock.release()

    def get_crawl_result(self):
        """파서가 처리할 결과를 큐에서 가져옴"""
        self._lock.acquire()
        try:
            if len(self._crawl_results) > 0:
                result = self._crawl_results.popleft()
                self._stats['crawl_results_processed'] += 1
                return result
            else:
                return None
        finally:
            self._lock.release()

    def has_crawl_results(self):
        """처리할 CrawlResult가 있는지 확인"""
        self._lock.acquire()
        try:
            result = len(self._crawl_results) > 0
            return result
        finally:
            self._lock.release()

    def crawl_result_count(self):
        """대기 중인 CrawlResult 수"""
        self._lock.acquire()
        try:
            count = len(self._crawl_results)
            return count
        finally:
            self._lock.release()

    # ============================================================
    # 파서 → 퍼저 (AttackSurface)
    # ============================================================

    def add_attack_surface(self, surface):
        """파서가 생성한 공격 표면을 큐에 추가"""
        surface_id = surface.get_id()

        self._lock.acquire()
        try:
            if surface_id in self._seen_surface_ids:
                self._stats['duplicates_skipped'] += 1
                return False

            self._attack_surfaces.append(surface)
            self._seen_surface_ids.add(surface_id)
            self._stats['surfaces_added'] += 1
            return True
        finally:
            self._lock.release()

    def get_attack_surface(self):
        """퍼저가 처리할 공격 표면을 큐에서 가져옴"""
        self._lock.acquire()
        try:
            if len(self._attack_surfaces) > 0:
                surface = self._attack_surfaces.popleft()
                self._stats['surfaces_processed'] += 1
                return surface
            else:
                return None
        finally:
            self._lock.release()

    def get_attack_surfaces(self, count=10):
        """여러 개의 공격 표면을 한번에 가져옴"""
        surfaces = []

        self._lock.acquire()
        try:
            fetch_count = min(count, len(self._attack_surfaces))
            for _ in range(fetch_count):
                surface = self._attack_surfaces.popleft()
                surfaces.append(surface)
                self._stats['surfaces_processed'] += 1
            return surfaces
        finally:
            self._lock.release()

    def has_attack_surfaces(self):
        """처리할 AttackSurface가 있는지 확인"""
        self._lock.acquire()
        try:
            result = len(self._attack_surfaces) > 0
            return result
        finally:
            self._lock.release()

    def attack_surface_count(self):
        """대기 중인 AttackSurface 수"""
        self._lock.acquire()
        try:
            count = len(self._attack_surfaces)
            return count
        finally:
            self._lock.release()

    # ============================================================
    # 통계 및 관리
    # ============================================================

    def get_stats(self):
        """통계 반환"""
        self._lock.acquire()
        try:
            stats = self._stats.copy()
            stats['crawl_results_pending'] = len(self._crawl_results)
            stats['surfaces_pending'] = len(self._attack_surfaces)
            stats['unique_surfaces'] = len(self._seen_surface_ids)
            return stats
        finally:
            self._lock.release()

    def clear(self):
        """모든 큐 초기화"""
        self._lock.acquire()
        try:
            self._crawl_results.clear()
            self._attack_surfaces.clear()
            self._seen_surface_ids.clear()
            self._stats = {
                'crawl_results_added': 0,
                'crawl_results_processed': 0,
                'surfaces_added': 0,
                'surfaces_processed': 0,
                'duplicates_skipped': 0,
            }
        finally:
            self._lock.release()

    def is_empty(self):
        """모든 큐가 비었는지 확인"""
        self._lock.acquire()
        try:
            crawl_empty = len(self._crawl_results) == 0
            surface_empty = len(self._attack_surfaces) == 0
            result = crawl_empty 및 surface_empty
            return result
        finally:
            self._lock.release()

    # ============================================================
    # 편의 메서드 (크롤러용 단순화)
    # ============================================================

    def add_page(self, page):
        """크롤러에서 간단하게 페이지 추가"""
        self._lock.acquire()
        try:
            self._crawl_results.append(page)
            self._stats['crawl_results_added'] += 1
        finally:
            self._lock.release()

    def get_page(self):
        """파서에서 간단하게 페이지 가져오기"""
        self._lock.acquire()
        try:
            if len(self._crawl_results) > 0:
                page = self._crawl_results.popleft()
                self._stats['crawl_results_processed'] += 1
                return page
            else:
                return None
        finally:
            self._lock.release()

    def has_pages(self):
        """처리할 페이지가 있는지"""
        self._lock.acquire()
        try:
            result = len(self._crawl_results) > 0
            return result
        finally:
            self._lock.release()
