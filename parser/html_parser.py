"""
html_parser.py
비동기 HTML 파서 코어 엔진 (보안 강화 운영 버전)
- 단일 책임 원칙을 준수하는 파서 엔진
- SSRF 방어 로직 통합 (초기 + 최종 URL 검증)
- 불변(Immutable) 설정 상수 관리
- 불필요한 헬퍼/테스트 코드/소멸자 제거 완료
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from types import MappingProxyType
from typing import Optional, TypedDict
from urllib.parse import urlparse

import aiohttp
from bs4 import BeautifulSoup, FeatureNotFound

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# ===== 불변 설정 상수 (Immutable Constants) =====
PARSERS: tuple[str, ...] = ("lxml", "html.parser", "html5lib")
ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})
ALLOWED_CONTENT_TYPES: frozenset[str] = frozenset({
    "text/html",
    "application/xhtml+xml",
    "text/xml",
    "application/xml",
})

# SSRF 방지용 차단 네트워크 (IPv4/IPv6 분리로 TypeError 방지)
BLOCKED_NETWORKS_V4: tuple = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
)

BLOCKED_NETWORKS_V6: tuple = (
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)

DEFAULT_HEADERS: MappingProxyType = MappingProxyType({
    "User-Agent": "AsyncScanner-Bot/1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Cache-Control": "no-cache",
})

DEFAULT_TIMEOUT: int = 10
DNS_TIMEOUT: int = 3
MAX_CONTENT_LENGTH: int = 50 * 1024 * 1024  # 50MB
MAX_CONNECTIONS: int = 100
MAX_CONNECTIONS_PER_HOST: int = 30
CHUNK_SIZE: int = 8192
MAX_REDIRECTS: int = 10


class ParseResult(TypedDict, total=False):
    """파싱 결과를 담는 타입 정의"""
    success: bool
    soup: Optional[BeautifulSoup]
    base_url: Optional[str]
    error: Optional[str]
    status_code: Optional[int]


class AsyncHTMLParser:
    """SSRF 방어 기능을 갖춘 비동기 HTML 파서 코어 엔진"""

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        headers: Optional[dict] = None
    ):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.headers = dict(DEFAULT_HEADERS) if headers is None else dict(headers)
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> AsyncHTMLParser:
        """비동기 컨텍스트 매니저 진입: 세션 생성"""
        connector = aiohttp.TCPConnector(
            limit=MAX_CONNECTIONS,
            limit_per_host=MAX_CONNECTIONS_PER_HOST,
        )
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers=self.headers,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        """비동기 컨텍스트 매니저 종료: 세션 자원 해제"""
        if self.session and not self.session.closed:
            await self.session.close()

    @staticmethod
    async def _is_safe_url(url: str) -> bool:
        """
        URL 안전성 검증: 스킴 확인 + DNS 해석 + 내부 IP 대역 차단
        
        주의: 이 검증은 1차 방어 수준이며, 완전한 DNS Rebinding 방어를 위해서는
        DNS 조회 후 연결 IP를 고정하고 재조회를 차단하는 추가 조치가 필요함
        """
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ALLOWED_SCHEMES:
                return False

            hostname = parsed.hostname
            if not hostname:
                return False

            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            loop = asyncio.get_running_loop()

            addrinfo = await asyncio.wait_for(
                loop.getaddrinfo(hostname, port),
                timeout=DNS_TIMEOUT,
            )

            for _, _, _, _, sockaddr in addrinfo:
                ip = ipaddress.ip_address(sockaddr[0])
                
                # IPv4/IPv6에 맞는 네트워크 목록 선택 (TypeError 방지)
                if ip.version == 4:
                    blocked_networks = BLOCKED_NETWORKS_V4
                else:
                    blocked_networks = BLOCKED_NETWORKS_V6
                
                if any(ip in network for network in blocked_networks):
                    return False

            return True

        except asyncio.TimeoutError:
            logger.debug(f"DNS 조회 타임아웃: {url}")
            return False
        except OSError as e:
            logger.debug(f"DNS 조회 실패: {url} - {e}")
            return False
        except (ValueError, TypeError) as e:
            logger.debug(f"URL 파싱 오류: {url} - {e}")
            return False

    @staticmethod
    def _is_valid_content_type(content_type: Optional[str]) -> bool:
        """응답의 Content-Type이 허용된 HTML 형식인지 확인"""
        if not content_type:
            return False
        main_type = content_type.split(";")[0].strip().lower()
        return main_type in ALLOWED_CONTENT_TYPES

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
        return BeautifulSoup(html, "html.parser")

    async def _read_content(self, response: aiohttp.ClientResponse) -> bytes:
        """스트리밍 방식으로 응답을 읽어 메모리 과부하(OOM) 방지"""
        content_length_header = response.headers.get("Content-Length")
        if content_length_header:
            try:
                content_length = int(content_length_header)
            except (ValueError, TypeError):
                content_length = None
            
            if content_length is not None and content_length > MAX_CONTENT_LENGTH:
                raise ValueError(f"컨텐츠 크기 제한 초과: {content_length} bytes")

        buffer = bytearray()
        async for chunk in response.content.iter_chunked(CHUNK_SIZE):
            buffer.extend(chunk)
            if len(buffer) > MAX_CONTENT_LENGTH:
                raise ValueError(f"컨텐츠 실제 크기 제한 초과: {len(buffer)} bytes")

        return bytes(buffer)

    async def parse(self, url: str) -> ParseResult:
        """
        URL로부터 HTML을 가져와 파싱
        
        aiohttp 내장 리다이렉트 사용 (allow_redirects=True)
        보안: 초기 URL + 최종 URL 검증으로 SSRF 방어
        
        주의: 중간 리다이렉트 경로는 검증하지 않음. 완전한 SSRF 방어가 필요하면
        allow_redirects=False로 수동 추적 방식을 사용해야 함.
        """
        if not self.session:
            return {
                "success": False,
                "error": "세션이 초기화되지 않았습니다. async with 구문을 사용하세요.",
                "base_url": url,
            }

        try:
            if not await self._is_safe_url(url):
                return {
                    "success": False,
                    "error": f"SSRF 보안 정책에 의해 차단됨: {url}",
                    "base_url": url,
                }

            async with self.session.get(
                url,
                allow_redirects=True,
                max_redirects=MAX_REDIRECTS
            ) as response:
                final_url = str(response.url)

                if not await self._is_safe_url(final_url):
                    return {
                        "success": False,
                        "error": f"리다이렉트 대상이 SSRF 정책에 의해 차단됨: {final_url}",
                        "base_url": final_url,
                    }

                if response.status >= 400:
                    return {
                        "success": False,
                        "error": f"HTTP {response.status} 에러",
                        "base_url": final_url,
                        "status_code": response.status,
                    }

                content_type = response.headers.get("Content-Type", "")
                if not self._is_valid_content_type(content_type):
                    return {
                        "success": False,
                        "error": f"허용되지 않는 Content-Type: {content_type}",
                        "base_url": final_url,
                        "status_code": response.status,
                    }

                raw = await self._read_content(response)

                encoding = response.charset or "utf-8"
                try:
                    html = raw.decode(encoding)
                except (UnicodeDecodeError, LookupError):
                    html = raw.decode("utf-8", errors="replace")

                soup = self._parse_html(html)

                return {
                    "success": True,
                    "soup": soup,
                    "base_url": final_url,
                    "status_code": response.status,
                    "error": None,
                }

        except asyncio.TimeoutError:
            return {"success": False, "error": "요청 타임아웃", "base_url": url}
        except aiohttp.TooManyRedirects:
            return {
                "success": False,
                "error": f"리다이렉트 횟수 초과 (최대: {MAX_REDIRECTS}회)",
                "base_url": url,
            }
        except aiohttp.ClientError as exc:
            return {
                "success": False,
                "error": f"HTTP 클라이언트 오류: {type(exc).__name__}",
                "base_url": url,
            }
        except ValueError as exc:
            return {
                "success": False,
                "error": str(exc),
                "base_url": url,
            }
        except Exception as exc:
            logger.exception("파서 예외 발생")
            return {
                "success": False,
                "error": f"예상치 못한 오류: {type(exc).__name__}",
                "base_url": url,
            }

    @staticmethod
    def parse_html_string(
        html: str,
        base_url: str = "",
        max_length: int = MAX_CONTENT_LENGTH
    ) -> ParseResult:
        """HTML 문자열을 직접 파싱 (크기 검사 포함)"""
        if not isinstance(html, str):
            return {
                "success": False,
                "error": f"잘못된 입력 타입: {type(html).__name__} (str 필요)",
                "base_url": base_url,
            }

        try:
            byte_size = len(html.encode("utf-8"))
            if byte_size > max_length:
                return {
                    "success": False,
                    "error": f"입력 크기 초과: {byte_size} > {max_length} bytes",
                    "base_url": base_url,
                }

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