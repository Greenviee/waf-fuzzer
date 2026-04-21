# core/models.py
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
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
# Team B에서 사용하는 DTO (기존 유지)
# ============================================================

@dataclass(slots=True)
class AttackSurface:
    """
    Shared DTO between crawler/parser and fuzzer engine.
    """
    url: str
    method: HttpMethod = HttpMethod.GET
    param_location: ParamLocation = ParamLocation.QUERY
    parameters: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    source_url: str | None = None
    description: str | None = None
    
    # 추가 필드 (크롤러에서 사용)
    depth: int = 0
    content_type: str | None = None
    
    def get_id(self) -> str:
        """고유 식별자 생성"""
        params_str = str(sorted(self.parameters.keys()))
        raw = f"{self.url}:{self.method.value}:{self.param_location.value}:{params_str}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]
    
    def to_dict(self) -> dict[str, Any]:
        """직렬화"""
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
    def from_dict(cls, data: dict[str, Any]) -> AttackSurface:
        """역직렬화"""
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


@dataclass(slots=True, frozen=True)
class Payload:
    """
    Structured payload metadata used by payload provider/reporter.
    """
    value: str
    attack_type: str
    risk_level: str


@dataclass(slots=True, frozen=True)
class FuzzingTask:
    """
    One concrete fuzzing unit generated from a surface.
    """
    surface: AttackSurface
    target_param: str
    payload: Payload


# ============================================================
# Team A - Crawler 전용 DTO
# ============================================================

@dataclass(slots=True)
class CrawlTask:
    """크롤링 작업 단위"""
    url: str
    depth: int = 0
    parent_url: str | None = None
    retry_count: int = 0
    priority: int = 0  # 높을수록 우선
    created_at: datetime = field(default_factory=datetime.now)
    
    def __lt__(self, other: CrawlTask) -> bool:
        """우선순위 큐 비교"""
        return self.priority > other.priority
    
    def to_dict(self) -> dict[str, Any]:
        return {
            'url': self.url,
            'depth': self.depth,
            'parent_url': self.parent_url,
            'retry_count': self.retry_count,
            'priority': self.priority,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CrawlTask:
        return cls(
            url=data['url'],
            depth=data.get('depth', 0),
            parent_url=data.get('parent_url'),
            retry_count=data.get('retry_count', 0),
            priority=data.get('priority', 0),
        )


@dataclass(slots=True)
class CrawlResult:
    """크롤러 → 파서 전달 데이터"""
    url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    body: str
    content_type: str
    response_time: float
    depth: int
    parent_url: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)
    cookies: dict[str, str] = field(default_factory=dict)
    content_length: int = 0
    is_dynamic: bool = False
    redirect_chain: list[str] = field(default_factory=list)
    
    def get_hash(self) -> str:
        """컨텐츠 해시"""
        return hashlib.md5(self.body.encode()).hexdigest()
    
    def to_dict(self) -> dict[str, Any]:
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


@dataclass
class CrawlStats:
    """크롤링 통계"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    skipped_requests: int = 0
    
    total_forms_found: int = 0
    total_links_found: int = 0
    total_apis_found: int = 0
    total_attack_surfaces: int = 0
    
    bytes_downloaded: int = 0
    
    start_time: datetime | None = None
    end_time: datetime | None = None
    
    errors_by_type: dict[str, int] = field(default_factory=dict)
    status_codes: dict[int, int] = field(default_factory=dict)
    
    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            return (datetime.now() - self.start_time).total_seconds()
        return 0.0
    
    @property
    def requests_per_second(self) -> float:
        return self.total_requests / self.duration if self.duration > 0 else 0.0
    
    @property
    def success_rate(self) -> float:
        return (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0.0
    
    def record_error(self, error_type: str) -> None:
        self.errors_by_type[error_type] = self.errors_by_type.get(error_type, 0) + 1
    
    def record_status(self, status_code: int) -> None:
        self.status_codes[status_code] = self.status_codes.get(status_code, 0) + 1
    
    def to_dict(self) -> dict[str, Any]:
        return {
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'skipped_requests': self.skipped_requests,
            'success_rate': f"{self.success_rate:.2f}%",
            'duration': f"{self.duration:.2f}s",
            'requests_per_second': f"{self.requests_per_second:.2f}",
            'bytes_downloaded': self.bytes_downloaded,
            'forms_found': self.total_forms_found,
            'links_found': self.total_links_found,
            'attack_surfaces': self.total_attack_surfaces,
            'errors_by_type': self.errors_by_type,
            'status_codes': self.status_codes,
        }
    # core/models.py 맨 아래에 추가

# ============================================================
# 팀 A → 팀 B 전달용 콜백 타입
# ============================================================

from typing import Callable, Awaitable

# AttackSurface를 받는 콜백 타입
SurfaceCallback = Callable[[AttackSurface], Awaitable[None] | None]