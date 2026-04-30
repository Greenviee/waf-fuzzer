# parsers/html_parser.py

"""
html_parser.py
순수 HTML 파서 코어 엔진 (리팩토링 완료)
- 단일 책임 원칙(SRP) 준수: 네트워크 통신 및 SSRF 검증은 SessionManager/URLFilter로 위임
- 불필요한 aiohttp 의존성 및 네트워크 로직 제거
- 순수하게 HTML 문자열을 BeautifulSoup 객체로 빠르고 안전하게 변환하는 역할만 수행
"""

from __future__ import annotations
import logging
from typing import Optional, TypedDict

from bs4 import BeautifulSoup, FeatureNotFound

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# ===== 불변 설정 상수 (Immutable Constants) =====
PARSERS: tuple[str, ...] = ("lxml", "html.parser", "html5lib")
MAX_CONTENT_LENGTH: int = 50 * 1024 * 1024  # 50MB


class ParseResult(TypedDict, total=False):
    """파싱 결과를 담는 타입 정의"""
    success: bool
    soup: Optional[BeautifulSoup]
    base_url: Optional[str]
    error: Optional[str]


class AsyncHTMLParser:
    """단일 책임 원칙을 준수하는 경량 HTML 파서 엔진"""

    @staticmethod
    def _parse_html(html: str) -> BeautifulSoup:
        """여러 파서를 순차적으로 시도하여 HTML 파싱 (폴백 로직)"""
        for parser in PARSERS:
            try:
                return BeautifulSoup(html, parser)
            except FeatureNotFound:
                continue
            except (TypeError, ValueError):
                continue
        # 모든 시도 실패 시 파이썬 내장 기본 파서 사용
        return BeautifulSoup(html, "html.parser")

    @staticmethod
    def parse_html_string(
            html: str,
            base_url: str = "",
            max_length: int = MAX_CONTENT_LENGTH
    ) -> ParseResult:
        """
        HTML 문자열을 직접 파싱 (크기 검사 포함)
        ✨ [핵심 수정] CPU 바운드 작업이므로 호출자(Engine) 측에서
        loop.run_in_executor()를 통해 비동기 블로킹 없이 실행되도록 설계되었습니다.
        """
        if not isinstance(html, str):
            return {
                "success": False,
                "error": f"잘못된 입력 타입: {type(html).__name__} (str 필요)",
                "base_url": base_url,
            }

        try:
            # 1. 크기 제한 검증 (메모리 과부하/OOM 방지)
            byte_size = len(html.encode("utf-8", errors="ignore"))
            if byte_size > max_length:
                return {
                    "success": False,
                    "error": f"입력 크기 초과: {byte_size} > {max_length} bytes",
                    "base_url": base_url,
                }

            # 2. 파싱 수행
            soup = AsyncHTMLParser._parse_html(html)
            return {
                "success": True,
                "soup": soup,
                "base_url": base_url,
                "error": None,
            }

        except (TypeError, ValueError, FeatureNotFound) as exc:
            return {
                "success": False,
                "error": f"파싱 오류: {type(exc).__name__}",
                "base_url": base_url,
            }
        except Exception as exc:
            logger.exception("파서 예외 발생")
            return {
                "success": False,
                "error": f"예상치 못한 오류: {type(exc).__name__}",
                "base_url": base_url,
            }