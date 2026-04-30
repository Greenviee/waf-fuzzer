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
from typing import Any, Callable, Awaitable, Dict, List, Union

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
# 핵심 서비스 DTO (AttackSurface & TokenDetector & PageData)
# ============================================================

class TokenDetector:
    """동적 토큰(CSRF, Nonce 등) 감지기"""
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
        return any(keyword in name.lower() for keyword in cls.TOKEN_KEYWORDS)

    @classmethod
    def is_token_value(cls, value: str) -> bool:
        if not value or len(value) < 16: return False
        if value.isdigit(): return False
        if value.lower() in cls.COMMON_WORDS: return False
        return any(re.match(pattern, value) for pattern in cls.HASH_PATTERNS)

    @classmethod
    def detect(cls, name: str, value: str, input_type: str = None) -> bool:
        if cls.is_token_name(name): return True
        if input_type == 'hidden' and cls.is_token_value(value): return True
        if cls.is_token_value(value):
            name_lower = name.lower() if name else ""
            weak_keywords = ['key', 'hash', 'secret', 'verify', 'check', 'valid']
            if any(kw in name_lower for kw in weak_keywords):
                return True
        return False


class PageData:
    """크롤러가 수집하여 큐에 쌓는 원시 데이터 모델"""
    def __init__(
            self,
            url: str,
            html: str,
            depth: int = 0,
            headers: Dict[str, str] = None,
            cookies: Dict[str, str] = None,
            dynamic_tokens: Dict[str, str] = None,
            soup: Any = None,  # ✨ [중요] 중복 파싱 방지를 위해 이미 생성된 BeautifulSoup 객체 저장
    ):
        self.url = url
        self.html = html
        self.depth = depth
        self.headers = headers if headers is not None else {}
        self.cookies = cookies if cookies is not None else {}
        self.dynamic_tokens = dynamic_tokens if dynamic_tokens is not None else {}
        self.soup = soup

    def __repr__(self) -> str:
        return (f"PageData(url='{self.url}', "
                f"depth={self.depth}, "
                f"tokens={len(self.dynamic_tokens)})")


@dataclass(slots=True)
class AttackSurface:
    """
    크롤러/파서 → 퍼저 전달용 공격 표면 DTO
    """
    url: str
    method: HttpMethod = HttpMethod.GET
    param_location: ParamLocation = ParamLocation.QUERY
    # ✨ [업데이트] 보안 진단을 위해 단일 str 뿐만 아니라 List[str] 형태의 배열 파라미터도 지원함
    parameters: Dict[str, Union[str, List[str]]] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    dynamic_tokens: Dict[str, str] = field(default_factory=dict)
    source_url: str | None = None
    description: str | None = None
    depth: int = 0
    content_type: str | None = None

    def get_id(self) -> str:
        """고유 식별자 생성"""
        params_str = str(sorted(self.parameters.keys()))
        raw = f"{self.url}:{self.method.value}:{self.param_location.value}:{params_str}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
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
            'content_type': self.content_type,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackSurface:
        return cls(
            url=data['url'],
            method=HttpMethod(data.get('method', 'GET')),
            param_location=ParamLocation(data.get('param_location', 'query')),
            parameters=data.get('parameters', {}),
            headers=data.get('headers', {}),
            cookies=data.get('cookies', {}),
            dynamic_tokens=data.get('dynamic_tokens', {}),
            source_url=data.get('source_url'),
            description=data.get('description'),
            depth=data.get('depth', 0),
            content_type=data.get('content_type'),
        )

# (이하 Payload, FuzzingTask, CrawlStats 등 기존과 동일)
@dataclass(slots=True, frozen=True)
class Payload:
    value: str
    attack_type: str
    risk_level: str

@dataclass(slots=True, frozen=True)
class FuzzingTask:
    surface: AttackSurface
    target_param: str
    payload: Payload

@dataclass
class CrawlStats:
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    skipped_requests: int = 0
    total_forms_found: int = 0
    total_links_found: int = 0
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
        return 0.0

    def record_error(self, error_type: str) -> None:
        self.errors_by_type[error_type] = self.errors_by_type.get(error_type, 0) + 1

    def record_status(self, status_code: int) -> None:
        self.status_codes[status_code] = self.status_codes.get(status_code, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            'successful_requests': self.successful_requests,
            'total_requests': self.total_requests,
            'forms_found': self.total_forms_found,
            'links_found': self.total_links_found,
            'duration': f"{self.duration:.2f}s",
            # ... 필요한 필드 추가
        }