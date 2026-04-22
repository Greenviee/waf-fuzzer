# core/models.py
"""
핵심 데이터 모델
Team A (크롤러/파서) + Team B (퍼저) 공통 사용
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Union
import hashlib


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class ParamLocation(str, Enum):
    QUERY = "query"
    BODY_FORM = "body_form"
    BODY_JSON = "body_json"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"


class CrawlStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


# ============================================================
# Team B에서 사용하는 DTO
# ============================================================

class AttackSurface:
    """
    크롤러/파서 → 퍼저 전달용 공격 표면 DTO
    """

    def __init__(
            self,
            url,
            method=HttpMethod.GET,
            param_location=ParamLocation.QUERY,
            parameters=None,
            headers=None,
            cookies=None,
            source_url=None,
            description=None,
            depth=0,
            content_type=None
    ):
        self.url = url
        self.method = method
        self.param_location = param_location
        self.parameters = parameters if parameters is not None else {}
        self.headers = headers if headers is not None else {}
        self.cookies = cookies if cookies is not None else {}
        self.source_url = source_url
        self.description = description
        self.depth = depth
        self.content_type = content_type

    def get_id(self):
        """고유 식별자 생성 (중복 체크용)"""
        params_str = str(sorted(self.parameters.keys()))
        raw = "%s:%s:%s:%s" % (self.url, self.method.value, self.param_location.value, params_str)
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    def to_dict(self):
        """JSON 직렬화용"""
        return {
            'id': self.get_id(),
            'url': self.url,
            'method': self.method.value,
            'param_location': self.param_location.value,
            'parameters': self.parameters,
            'headers': self.headers,
            'cookies': self.cookies,
            'source_url': self.source_url,
            'description': self.description,
            'depth': self.depth,
        }

    @classmethod
    def from_dict(cls, data):
        """JSON 역직렬화용"""
        return cls(
            url=data['url'],
            method=HttpMethod(data.get('method', 'GET')),
            param_location=ParamLocation(data.get('param_location', 'query')),
            parameters=data.get('parameters', {}),
            headers=data.get('headers', {}),
            cookies=data.get('cookies', {}),
            source_url=data.get('source_url'),
            description=data.get('description'),
            depth=data.get('depth', 0),
        )


class Payload:
    """페이로드 메타데이터"""

    def __init__(self, value, attack_type, risk_level):
        self.value = value
        self.attack_type = attack_type
        self.risk_level = risk_level


class FuzzingTask:
    """퍼징 작업 단위"""

    def __init__(self, surface, target_param, payload):
        self.surface = surface
        self.target_param = target_param
        self.payload = payload


# ============================================================
# Team A - Crawler 전용 DTO
# ============================================================

class CrawlTask:
    """크롤링 작업 단위"""

    def __init__(
            self,
            url,
            depth=0,
            parent_url=None,
            retry_count=0,
            priority=0,
            created_at=None
    ):
        self.url = url
        self.depth = depth
        self.parent_url = parent_url
        self.retry_count = retry_count
        self.priority = priority
        self.created_at = created_at if created_at is not None else datetime.now()

    def __lt__(self, other):
        """우선순위 큐 비교 (priority 높을수록 먼저)"""
        return self.priority > other.priority

    def to_dict(self):
        return {
            'url': self.url,
            'depth': self.depth,
            'parent_url': self.parent_url,
            'retry_count': self.retry_count,
            'priority': self.priority,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            url=data['url'],
            depth=data.get('depth', 0),
            parent_url=data.get('parent_url'),
            retry_count=data.get('retry_count', 0),
            priority=data.get('priority', 0),
        )


class CrawlResult:
    """크롤러 → 파서 전달 데이터"""

    def __init__(
            self,
            url,
            final_url,
            status_code,
            headers,
            body,
            content_type,
            response_time,
            depth,
            parent_url=None,
            timestamp=None,
            cookies=None,
            content_length=0,
            is_dynamic=False,
            redirect_chain=None
    ):
        self.url = url
        self.final_url = final_url
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.content_type = content_type
        self.response_time = response_time
        self.depth = depth
        self.parent_url = parent_url
        self.timestamp = timestamp if timestamp is not None else datetime.now()
        self.cookies = cookies if cookies is not None else {}
        self.content_length = content_length
        self.is_dynamic = is_dynamic
        self.redirect_chain = redirect_chain if redirect_chain is not None else []

    def get_hash(self):
        """컨텐츠 해시 (중복 페이지 감지용)"""
        return hashlib.md5(self.body.encode()).hexdigest()

    def to_dict(self):
        return {
            'url': self.url,
            'final_url': self.final_url,
            'status_code': self.status_code,
            'content_type': self.content_type,
            'response_time': self.response_time,
            'depth': self.depth,
            'parent_url': self.parent_url,
            'timestamp': self.timestamp.isoformat(),
            'content_length': self.content_length,
            'is_dynamic': self.is_dynamic,
            'body_hash': self.get_hash(),
        }


class CrawlStats:
    """크롤링 통계"""

    def __init__(self):
        # 요청 카운트
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.skipped_requests = 0

        # 발견 항목
        self.total_forms_found = 0
        self.total_links_found = 0
        self.total_apis_found = 0
        self.total_attack_surfaces = 0

        # 데이터
        self.bytes_downloaded = 0

        # 시간
        self.start_time = None
        self.end_time = None

        # 상세 통계
        self.errors_by_type = {}
        self.status_codes = {}

    @property
    def duration(self):
        """소요 시간 (초)"""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            return (datetime.now() - self.start_time).total_seconds()
        return 0.0

    @property
    def requests_per_second(self):
        """초당 요청 수"""
        if self.duration > 0:
            return self.total_requests / self.duration
        return 0.0

    @property
    def success_rate(self):
        """성공률 (%)"""
        if self.total_requests > 0:
            return self.successful_requests / self.total_requests * 100
        return 0.0

    def record_error(self, error_type):
        """에러 기록"""
        if error_type in self.errors_by_type:
            self.errors_by_type[error_type] += 1
        else:
            self.errors_by_type[error_type] = 1

    def record_status(self, status_code):
        """상태 코드 기록"""
        if status_code in self.status_codes:
            self.status_codes[status_code] += 1
        else:
            self.status_codes[status_code] = 1

    def start(self):
        """크롤링 시작 시간 기록"""
        self.start_time = datetime.now()

    def finish(self):
        """크롤링 종료 시간 기록"""
        self.end_time = datetime.now()

    def reset(self):
        """통계 초기화"""
        self.__init__()

    def to_dict(self):
        return {
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'skipped_requests': self.skipped_requests,
            'success_rate': "%.2f%%" % self.success_rate,
            'duration': "%.2f초" % self.duration,
            'requests_per_second': "%.2f" % self.requests_per_second,
            'bytes_downloaded': self.bytes_downloaded,
            'forms_found': self.total_forms_found,
            'links_found': self.total_links_found,
            'attack_surfaces': self.total_attack_surfaces,
            'errors_by_type': self.errors_by_type,
            'status_codes': self.status_codes,
        }

# ============================================================
# 팀 A → 팀 B 콜백 타입 (참고용 주석)
# ============================================================

# SurfaceCallback: AttackSurface를 받는 콜백 함수
# 동기: def callback(surface: AttackSurface) -> None
# 비동기: async def callback(surface: AttackSurface) -> None