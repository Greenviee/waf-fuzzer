# core/__init__.py
"""
Core 모듈
공통 데이터 모델 및 큐 관리
"""

from .models import (
    # Enums
    HttpMethod,
    ParamLocation,
    CrawlStatus,

    # Team B DTOs
    AttackSurface,
    Payload,
    FuzzingTask,

    # Team A DTOs
    CrawlTask,
    CrawlResult,
    CrawlStats,
)

from .queue_manager import QueueManager

__all__ = [
    # Enums
    'HttpMethod',
    'ParamLocation',
    'CrawlStatus',

    # DTOs
    'AttackSurface',
    'Payload',
    'FuzzingTask',
    'CrawlTask',
    'CrawlResult',
    'CrawlStats',

    # Manager
    'QueueManager',
]