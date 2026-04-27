"""
핵심 데이터 모델 (Unified Core Models)
Team A (Crawler/Parser) + Team B (Fuzzer) 통합 운영 버전
"""

from __future__ import annotations
import re
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


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
# 핵심 서비스 DTO (AttackSurface & TokenDetector)
# ============================================================

class TokenDetector:
    """
    동적 토큰(CSRF, Nonce 등) 감지기
    파서가 추출한 파라미터 중 조작하면 안 되는 토큰을 자동으로 찾아냅니다.
    """
    TOKEN_KEYWORDS = [
        'csrf', 'xsrf', 'token', 'nonce', 'auth', '_token', 'authenticity',
        'verification', 'user_token', 'form_token', 'request_token', 'anti_csrf', '_csrf'
    ]

    HASH_PATTERNS = [
        r'^[a-fA-F0-9]{32}$', r'^[a-fA-F0-9]{40}$', r'^[a-fA-F0-9]{64}$',
        r'^[A-Za-z0-9+/]{20,}={0,2}$', r'^[a-fA-F0-9-]{36}$', r'^[a-zA-Z0-9_-]{16,}$'
    ]

    COMMON_WORDS = ['submit', 'login', 'search', 'password', 'username', 'button', 'reset', 'cancel']

    @classmethod
    def is_token_name(cls, name: str) -> bool:
        if not name: return False
        name_lower = name.lower()
        return any(keyword in name_lower for keyword in cls.TOKEN_KEYWORDS)

    @classmethod
    def is_token_value(cls, value: str) -> bool:
        if not value or len(value) < 16: return False
        if value.isdigit(): return False
        if value.lower() in cls.COMMON_WORDS: return False
        return any(re.match(pattern, value) for pattern in cls.HASH_PATTERNS)

    @classmethod
    def detect(cls, name: str, value: str, input_type: str = None) -> bool:
        """동적 토큰 여부 종합 판단"""
        if cls.is_token_name(name): return True
        if input_type == 'hidden' and cls.is_token_value(value): return True
        if cls.is_token_value(value):
            name_lower = name.lower() if name else ""
            weak_keywords = ['key', 'hash', 'secret', 'verify', 'check', 'valid']
            if any(kw in name_lower for kw in weak_keywords):
                return True
        return False


class AttackSurface:
    """
    크롤러/파서 → 퍼저 전달용 공격 표면 DTO
    """
    def __init__(
            self,
            url: str,
            method: HttpMethod = HttpMethod.GET,
            param_location: ParamLocation = ParamLocation.QUERY,
            parameters: Dict[str, Any] = None,
            headers: Dict[str, str] = None,
            cookies: Dict[str, str] = None,
            dynamic_tokens: List[str] = None,
            source_url: str = None,
            description: str = None,
            depth: int = 0,
            content_type: str = None
    ):
        self.url = url
        self.method = method
        self.param_location = param_location
        self.parameters = parameters if parameters is not None else {}
        self.headers = headers if headers is not None else {}
        self.cookies = cookies if cookies is not None else {}
        self.dynamic_tokens = dynamic_tokens if dynamic_tokens is not None else []
        self.source_url = source_url
        self.description = description
        self.depth = depth
        self.content_type = content_type

    def get_id(self) -> str:
        """고유 ID 생성 (URL + Method + Location + 파라미터 키 조합 해시)"""
        param_keys = sorted(self.parameters.keys())
        unique_str = (
            f"{self.url}|"
            f"{self.method.value}|"
            f"{self.param_location.value}|"
            f"{','.join(param_keys)}"
        )
        return hashlib.md5(unique_str.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """JSON 직렬화용"""
        return {
            'id': self.get_id(),
            'url': self.url,
            'method': self.method.value,
            'param_location': self.param_location.value,
            'parameters': self.parameters,
            'headers': self.headers,
            'cookies': self.cookies,
            'dynamic_tokens': self.dynamic_tokens,
            'source_url': self.source_url,
            'description': self.description,
            'depth': self.depth,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttackSurface:
        """JSON 역직렬화용"""
        return cls(
            url=data['url'],
            method=HttpMethod(data.get('method', 'GET')),
            param_location=ParamLocation(data.get('param_location', 'query')),
            parameters=data.get('parameters', {}),
            headers=data.get('headers', {}),
            cookies=data.get('cookies', {}),
            dynamic_tokens=data.get('dynamic_tokens', []),
            source_url=data.get('source_url'),
            description=data.get('description'),
            depth=data.get('depth', 0),
        )

    def __repr__(self) -> str:
        return (f"AttackSurface(url='{self.url}', method={self.method.value}, "
                f"params={list(self.parameters.keys())}, dynamic_tokens={self.dynamic_tokens})")


# ============================================================
# Team A - Crawler / Parser 전용 데이터 모델
# ============================================================

@dataclass(slots=True)
class CrawlTask:
    """크롤링 작업 단위"""
    url: str
    depth: int = 0
    parent_url: str | None = None
    retry_count: int = 0
    priority: int = 0
    created_at: datetime = field(default_factory=datetime.now)

    def __lt__(self, other: CrawlTask) -> bool:
        return self.priority > other.priority

    def to_dict(self) -> dict[str, Any]:
        return {
            'url': self.url, 'depth': self.depth, 'parent_url': self.parent_url,
            'retry_count': self.retry_count, 'priority': self.priority,
        }

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
        return hashlib.md5(self.body.encode()).hexdigest()

class PageData:
    """파싱을 위해 정제된 페이지 데이터"""
    def __init__(self, url: str, html: str, depth: int = 0):
        self.url = url
        self.html = html
        self.depth = depth

    def __repr__(self) -> str:
        return f"PageData(url='{self.url}', depth={self.depth})"

@dataclass
class CrawlStats:
    """크롤링 통계 관리"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    skipped_requests: int = 0
    total_forms_found: int = 0
    total_links_found: int = 0
    total_attack_surfaces: int = 0
    bytes_downloaded: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    errors_by_type: Dict[str, int] = field(default_factory=dict)
    status_codes: Dict[int, int] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        curr_end = self.end_time or datetime.now()
        return (curr_end - self.start_time).total_seconds() if self.start_time else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            'total_requests': self.total_requests,
            'success_rate': f"{(self.successful_requests/self.total_requests*100 if self.total_requests else 0):.2f}%",
            'duration': f"{self.duration:.2f}s",
            'attack_surfaces': self.total_attack_surfaces,
            'errors': self.errors_by_type
        }


# ============================================================
# 팀 A → 팀 B 전달용 콜백 타입
# ============================================================

from typing import Callable, Awaitable

# AttackSurface를 받는 콜백 타입
SurfaceCallback = Callable[[AttackSurface], Awaitable[None] | None]