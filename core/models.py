# core/models.py

from typing import Dict, Any,  List
from enum import Enum
import re
import hashlib  # 추가!


class HttpMethod(Enum):
    """HTTP 메서드"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


class ParamLocation(Enum):
    """파라미터 위치"""
    QUERY = "query"
    BODY_FORM = "body_form"
    BODY_JSON = "body_json"
    HEADER = "header"
    COOKIE = "cookie"


class AttackSurface:
    """
    파서와 퍼저 사이의 데이터 규격 (DTO)
    """

    def __init__(
            self,
            url: str,
            method: "HttpMethod",
            param_location: "ParamLocation",
            parameters: Dict[str, Any] = None,
            headers: Dict[str, str] = None,
            cookies: Dict[str, str] = None,
            dynamic_tokens: List[str] = None,
            source_url: str = None,
            description: str = None
    ):
        """
        AttackSurface 초기화

        Args:
            url: 공격 대상 URL
            method: HTTP 메서드
            param_location: 파라미터 위치
            parameters: 파라미터 딕셔너리
            headers: 헤더 딕셔너리
            cookies: 쿠키 딕셔너리
            dynamic_tokens: 동적 토큰 이름 리스트
            source_url: 이 폼을 발견한 페이지 URL
            description: 설명
        """
        self.url = url
        self.method = method
        self.param_location = param_location
        self.parameters = parameters if parameters is not None else {}
        self.headers = headers if headers is not None else {}
        self.cookies = cookies if cookies is not None else {}
        self.dynamic_tokens = dynamic_tokens if dynamic_tokens is not None else []
        self.source_url = source_url
        self.description = description

    def get_id(self) -> str:
        """
        고유 ID 생성 (중복 체크용)

        URL + Method + ParamLocation + 파라미터 키 조합으로 해시 생성

        Returns:
            str: MD5 해시 ID
        """
        param_keys = sorted(self.parameters.keys())
        unique_str = (
            f"{self.url}|"
            f"{self.method.value}|"
            f"{self.param_location.value}|"
            f"{','.join(param_keys)}"
        )
        return hashlib.md5(unique_str.encode()).hexdigest()

    def __repr__(self) -> str:
        return (
            f"AttackSurface("
            f"url='{self.url}', "
            f"method={self.method.value}, "
            f"param_location={self.param_location.value}, "
            f"params={list(self.parameters.keys())}, "
            f"dynamic_tokens={self.dynamic_tokens})"
        )


class PageData:
    """크롤링된 페이지 데이터"""

    def __init__(
            self,
            url: str,
            html: str,
            depth: int = 0
    ):
        """
        PageData 초기화

        Args:
            url: 페이지 URL
            html: HTML 콘텐츠
            depth: 크롤링 깊이
        """
        self.url = url
        self.html = html
        self.depth = depth

    def __repr__(self) -> str:
        return f"PageData(url='{self.url}', depth={self.depth})"


class TokenDetector:
    """동적 토큰 감지기"""

    # 이름 기반 매칭 키워드
    TOKEN_KEYWORDS = [
        'csrf',
        'xsrf',
        'token',
        'nonce',
        'auth',
        '_token',
        'authenticity',
        'verification',
        'user_token',
        'form_token',
        'request_token',
        'anti_csrf',
        '_csrf',
    ]

    # 값 기반 매칭 패턴 (16자리 이상 해시/UUID)
    HASH_PATTERNS = [
        r'^[a-fA-F0-9]{32}$',
        r'^[a-fA-F0-9]{40}$',
        r'^[a-fA-F0-9]{64}$',
        r'^[A-Za-z0-9+/]{20,}={0,2}$',
        r'^[a-fA-F0-9-]{36}$',
        r'^[a-zA-Z0-9_-]{16,}$',
    ]

    # 제외할 일반적인 단어
    COMMON_WORDS = [
        'submit',
        'login',
        'search',
        'password',
        'username',
        'button',
        'reset',
        'cancel',
    ]

    def __init__(self):
        """TokenDetector 초기화"""
        pass

    @classmethod
    def is_token_name(cls, name: str) -> bool:
        """
        이름 기반 토큰 감지

        Args:
            name: 파라미터 이름

        Returns:
            bool: 토큰 이름 여부
        """
        if not name:
            return False

        name_lower = name.lower()
        return any(keyword in name_lower for keyword in cls.TOKEN_KEYWORDS)

    @classmethod
    def is_token_value(cls, value: str) -> bool:
        """
        값 기반 토큰 감지

        Args:
            value: 파라미터 값

        Returns:
            bool: 토큰 값 여부
        """
        if not value 또는 len(value) < 16:
            return False

        if value.isdigit():
            return False

        if value.lower() in cls.COMMON_WORDS:
            return False

        return any(re.match(pattern, value) for pattern in cls.HASH_PATTERNS)

    @classmethod
    def detect(cls, name: str, value: str, input_type: str = None) -> bool:
        """
        동적 토큰 여부 종합 판단

        Args:
            name: 파라미터 이름
            value: 파라미터 값
            input_type: input 타입 (hidden 등)

        Returns:
            bool: 동적 토큰 여부
        """
        if cls.is_token_name(name):
            return True

        if input_type == 'hidden' 및 cls.is_token_value(value):
            return True

        if cls.is_token_value(value):
            name_lower = name.lower() if name else ""
            weak_keywords = ['key', 'hash', 'secret', 'verify', 'check', 'valid']
            if any(kw in name_lower for kw in weak_keywords):
                return True

        return False
