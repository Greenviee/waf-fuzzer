# core/queue_manager.py
"""
큐 관리자
크롤러 → 파서 → 퍼저 간의 데이터 전달을 관리

담당: Team A 공통
"""

import threading
from collections import deque
from datetime import datetime

from utils.logger import get_logger

logger = get_logger(__name__)


class QueueManager:
    """
    작업 큐 관리자

    역할:
    1. 크롤러 → 파서: CrawlResult 전달
    2. 파서 → 퍼저: AttackSurface 전달

    사용 예시:
        queue_manager = QueueManager()

        # 크롤러에서
        queue_manager.add_crawl_result(result)

        # 파서에서
        result = queue_manager.get_crawl_result()
        queue_manager.add_attack_surface(surface)

        # 퍼저에서
        surface = queue_manager.get_attack_surface()
    """

    def __init__(self, max_size=10000):
        """
        큐 관리자 초기화

        Args:
            max_size: 각 큐의 최대 크기
        """
        self.max_size = max_size

        # 크롤러 → 파서 큐
        self._crawl_results = deque(maxlen=max_size)

        # 파서 → 퍼저 큐
        self._attack_surfaces = deque(maxlen=max_size)

        # 중복 체크용 (AttackSurface ID)
        self._seen_surface_ids = set()

        # 스레드 안전성
        self._lock = threading.Lock()

        # 통계
        self._stats = {
            'crawl_results_added': 0,
            'crawl_results_processed': 0,
            'surfaces_added': 0,
            'surfaces_processed': 0,
            'duplicates_skipped': 0,
        }

        logger.debug("QueueManager 초기화 완료")

    # ============================================================
    # 크롤러 → 파서 (CrawlResult)
    # ============================================================

    def add_crawl_result(self, result):
        """
        크롤러가 수집한 결과를 큐에 추가

        Args:
            result: CrawlResult 객체
        """
        with self._lock:
            self._crawl_results.append(result)
            self._stats['crawl_results_added'] += 1

        logger.debug("CrawlResult 추가: %s", result.url)

    def get_crawl_result(self):
        """
        파서가 처리할 결과를 큐에서 가져옴

        Returns:
            CrawlResult 또는 None
        """
        with self._lock:
            if self._crawl_results:
                result = self._crawl_results.popleft()
                self._stats['crawl_results_processed'] += 1
                return result
        return None

    def has_crawl_results(self):
        """처리할 CrawlResult가 있는지 확인"""
        with self._lock:
            return len(self._crawl_results) > 0

    def crawl_result_count(self):
        """대기 중인 CrawlResult 수"""
        with self._lock:
            return len(self._crawl_results)

    # ============================================================
    # 파서 → 퍼저 (AttackSurface)
    # ============================================================

    def add_attack_surface(self, surface):
        """
        파서가 생성한 공격 표면을 큐에 추가

        Args:
            surface: AttackSurface 객체

        Returns:
            추가 성공 여부 (중복이면 False)
        """
        surface_id = surface.get_id()

        with self._lock:
            # 중복 체크
            if surface_id in self._seen_surface_ids:
                self._stats['duplicates_skipped'] += 1
                logger.debug("중복 Surface 스킵: %s", surface_id)
                return False

            # 큐에 추가
            self._attack_surfaces.append(surface)
            self._seen_surface_ids.add(surface_id)
            self._stats['surfaces_added'] += 1

        logger.debug("AttackSurface 추가: %s %s", surface.method.value, surface.url)
        return True

    def get_attack_surface(self):
        """
        퍼저가 처리할 공격 표면을 큐에서 가져옴

        Returns:
            AttackSurface 또는 None
        """
        with self._lock:
            if self._attack_surfaces:
                surface = self._attack_surfaces.popleft()
                self._stats['surfaces_processed'] += 1
                return surface
        return None

    def get_attack_surfaces(self, count=10):
        """
        여러 개의 공격 표면을 한번에 가져옴

        Args:
            count: 가져올 개수

        Returns:
            AttackSurface 리스트
        """
        surfaces = []
        with self._lock:
            for _ in range(min(count, len(self._attack_surfaces))):
                surface = self._attack_surfaces.popleft()
                surfaces.append(surface)
                self._stats['surfaces_processed'] += 1
        return surfaces

    def has_attack_surfaces(self):
        """처리할 AttackSurface가 있는지 확인"""
        with self._lock:
            return len(self._attack_surfaces) > 0

    def attack_surface_count(self):
        """대기 중인 AttackSurface 수"""
        with self._lock:
            return len(self._attack_surfaces)

    # ============================================================
    # 통계 및 관리
    # ============================================================

    def get_stats(self):
        """통계 반환"""
        with self._lock:
            stats = self._stats.copy()
            stats['crawl_results_pending'] = len(self._crawl_results)
            stats['surfaces_pending'] = len(self._attack_surfaces)
            stats['unique_surfaces'] = len(self._seen_surface_ids)
        return stats

    def clear(self):
        """모든 큐 초기화"""
        with self._lock:
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
        logger.info("QueueManager 초기화됨")

    def is_empty(self):
        """모든 큐가 비었는지 확인"""
        with self._lock:
            return (len(self._crawl_results) == 0 and
                    len(self._attack_surfaces) == 0)

    # ============================================================
    # 편의 메서드 (크롤러용 단순화)
    # ============================================================

    def add_page(self, page):
        """
        크롤러에서 간단하게 페이지 추가 (CrawlResult 대신 사용 가능)

        Args:
            page: url, html, depth 속성을 가진 객체
        """
        # CrawlResult로 변환하지 않고 직접 저장
        with self._lock:
            self._crawl_results.append(page)
            self._stats['crawl_results_added'] += 1

    def get_page(self):
        """
        파서에서 간단하게 페이지 가져오기

        Returns:
            페이지 객체 또는 None
        """
        return self.get_crawl_result()

    def has_pages(self):
        """처리할 페이지가 있는지"""
        return self.has_crawl_results()