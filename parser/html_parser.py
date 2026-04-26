"""
Async HTML Parser Module for Web Vulnerability Scanner
비동기 HTTP 요청을 통한 고성능 HTML 파싱 모듈
"""

import asyncio
import logging
import ipaddress
import socket
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from typing import Optional, Dict, Set, Any, List
import aiohttp
import aiofiles
from aiohttp import ClientTimeout, ClientSession, TCPConnector
import ssl

# 상수 정의
class AsyncParserConstants:
    # 파서 우선순위
    PARSERS = ['lxml', 'html.parser', 'html5lib']
    
    # HTTP 설정
    DEFAULT_TIMEOUT = 10
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    CHUNK_SIZE = 8192
    MAX_CONNECTIONS = 100
    MAX_CONNECTIONS_PER_HOST = 30
    
    # 허용할 Content-Type
    ALLOWED_CONTENT_TYPES = {
        'text/html',
        'application/xhtml+xml',
        'text/xml',
        'application/xml'
    }
    
    # 차단할 내부 네트워크 대역
    BLOCKED_NETWORKS = [
        '127.0.0.0/8',      # localhost
        '10.0.0.0/8',       # Private Class A
        '172.16.0.0/12',    # Private Class B
        '192.168.0.0/16',   # Private Class C
        '169.254.0.0/16',   # Link-local
        '224.0.0.0/4',      # Multicast
        '::1/128',          # IPv6 localhost
        'fc00::/7',         # IPv6 private
        'fe80::/10',        # IPv6 link-local
    ]
    
    # HTTP 헤더
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (AsyncScanner-Bot-v1.0)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'ko-KR,ko;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
        'Cache-Control': 'no-cache'
    }

# 로깅 설정
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

class AsyncSSRFProtection:
    """비동기 SSRF 공격 방지 클래스"""
    
    def __init__(self, allowed_schemes: Optional[Set[str]] = None):
        self.allowed_schemes = allowed_schemes or {'http', 'https'}
        self.blocked_networks = [ipaddress.ip_network(net) for net in AsyncParserConstants.BLOCKED_NETWORKS]
        self._dns_cache = {}  # 성능을 위한 DNS 캐시
        
    async def is_safe_url(self, url: str) -> bool:
        """
        비동기로 URL 안전성 검증
        
        Args:
            url (str): 검증할 URL
            
        Returns:
            bool: 안전한 URL 여부
        """
        try:
            # 1. URL 정규화
            normalized_url = self._normalize_url_strict(url)
            parsed = urlparse(normalized_url)
            
            # 2. 스킴 검증
            if parsed.scheme not in self.allowed_schemes:
                logger.warning(f"허용되지 않은 스킴: {parsed.scheme}")
                return False
            
            # 3. 호스트명 검증
            if not parsed.hostname:
                logger.warning("호스트명이 없습니다")
                return False
            
            # 4. DNS 해석 및 IP 검증 (비동기)
            resolved_ips = await self._resolve_hostname_async(parsed.hostname)
            for ip_str in resolved_ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if self._is_blocked_ip(ip):
                        logger.warning(f"차단된 IP로 해석됨: {parsed.hostname} -> {ip}")
                        return False
                except ValueError:
                    logger.warning(f"잘못된 IP 주소: {ip_str}")
                    return False
            
            # 5. 호스트명 패턴 검증
            if not self._is_safe_hostname(parsed.hostname):
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"URL 검증 오류: {str(e)}")
            return False
    
    def _normalize_url_strict(self, url: str) -> str:
        """엄격한 URL 정규화"""
        if not url or not isinstance(url, str):
            raise ValueError("잘못된 URL")
        
        # 공백 및 제어 문자 제거
        url = url.strip()
        url = ''.join(char for char in url if ord(char) >= 32)
        
        # 프로토콜 상대 URL 처리
        if url.startswith('//'):
            url = 'https:' + url
        
        # 스킴이 없으면 추가
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'https://' + url
        
        return url
    
    async def _resolve_hostname_async(self, hostname: str) -> List[str]:
        """비동기 DNS 해석"""
        # 캐시 확인
        if hostname in self._dns_cache:
            logger.debug(f"DNS 캐시 사용: {hostname}")
            return self._dns_cache[hostname]
        
        try:
            # IPv4 주소인지 먼저 확인
            ipaddress.ip_address(hostname)
            self._dns_cache[hostname] = [hostname]
            return [hostname]
        except ValueError:
            pass
        
        resolved_ips = []
        
        try:
            # asyncio를 이용한 비동기 DNS 해석
            loop = asyncio.get_event_loop()
            
            # IPv4 해석
            try:
                ipv4_result = await loop.getaddrinfo(
                    hostname, None, 
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM
                )
                for result in ipv4_result:
                    ip = result[4][0]
                    if ip not in resolved_ips:
                        resolved_ips.append(ip)
            except socket.gaierror:
                pass
            
            # IPv6 해석
            try:
                ipv6_result = await loop.getaddrinfo(
                    hostname, None,
                    family=socket.AF_INET6,
                    type=socket.SOCK_STREAM
                )
                for result in ipv6_result:
                    ip = result[4][0]
                    if ip not in resolved_ips:
                        resolved_ips.append(ip)
            except socket.gaierror:
                pass
            
            if not resolved_ips:
                raise ValueError(f"DNS 해석 실패: {hostname}")
            
            # 캐시에 저장 (성공한 경우만)
            self._dns_cache[hostname] = resolved_ips
            logger.debug(f"비동기 DNS 해석 결과: {hostname} -> {resolved_ips}")
            
            return resolved_ips
            
        except Exception as e:
            logger.error(f"비동기 DNS 해석 오류: {hostname} - {str(e)}")
            raise
    
    def _is_blocked_ip(self, ip: ipaddress._BaseAddress) -> bool:
        """IP가 차단된 네트워크 대역에 속하는지 확인"""
        for network in self.blocked_networks:
            if ip in network:
                return True
        return False
    
    def _is_safe_hostname(self, hostname: str) -> bool:
        """호스트명이 안전한지 확인"""
        dangerous_patterns = [
            'localhost',
            '0.0.0.0',
            'metadata.google.internal',  # GCP 메타데이터
            '169.254.169.254',          # AWS 메타데이터
            'metadata.azure.com',        # Azure 메타데이터
        ]
        
        hostname_lower = hostname.lower()
        for pattern in dangerous_patterns:
            if pattern in hostname_lower:
                logger.warning(f"위험한 호스트명 패턴 감지: {hostname}")
                return False
        
        return True

class AsyncHTMLParser:
    """비동기 HTML 파서"""
    
    def __init__(self, 
                 timeout: int = AsyncParserConstants.DEFAULT_TIMEOUT,
                 verify_ssl: bool = True,
                 max_content_length: int = AsyncParserConstants.MAX_CONTENT_LENGTH,
                 max_connections: int = AsyncParserConstants.MAX_CONNECTIONS):
        """
        AsyncHTMLParser 초기화
        
        Args:
            timeout (int): HTTP 요청 타임아웃
            verify_ssl (bool): SSL 인증서 검증 여부
            max_content_length (int): 최대 콘텐츠 크기
            max_connections (int): 최대 동시 연결 수
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_content_length = max_content_length
        self.max_connections = max_connections
        
        self.ssrf_protection = AsyncSSRFProtection()
        self.session = None
        self._closed = False
        
    async def __aenter__(self):
        """비동기 컨텍스트 매니저 진입"""
        await self._ensure_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """비동기 컨텍스트 매니저 종료"""
        await self.close()
    
    async def _ensure_session(self):
        """세션이 없으면 생성"""
        if self.session is None or self.session.closed:
            self.session = await self._create_session()
    
    async def _create_session(self) -> ClientSession:
        """비동기 HTTP 세션 생성"""
        # SSL 컨텍스트 설정
        ssl_context = None
        if not self.verify_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        # 커넥터 설정
        connector = TCPConnector(
            limit=self.max_connections,
            limit_per_host=AsyncParserConstants.MAX_CONNECTIONS_PER_HOST,
            ssl=ssl_context,
            enable_cleanup_closed=True
        )
        
        # 타임아웃 설정
        timeout = ClientTimeout(
            total=self.timeout,
            connect=self.timeout // 3,
            sock_read=self.timeout // 2
        )
        
        session = ClientSession(
            headers=AsyncParserConstants.DEFAULT_HEADERS,
            connector=connector,
            timeout=timeout,
            raise_for_status=False  # 수동으로 처리
        )
        
        return session
    
    async def parse_from_url(self, url: str) -> Dict[str, Any]:
        """
        비동기로 URL에서 HTML을 가져와 파싱
        
        Args:
            url (str): 대상 URL
            
        Returns:
            Dict[str, Any]: 파싱 결과
        """
        try:
            logger.info(f"비동기 URL 파싱 시작: {url}")
            
            # 1. 세션 확인
            await self._ensure_session()
            
            # 2. 초기 URL 검증
            if not await self.ssrf_protection.is_safe_url(url):
                return {
                    'success': False,
                    'error': 'SSRF 보안 정책에 의해 차단된 URL',
                    'base_url': url
                }
            
            # 3. 비동기 HTTP 요청 (리다이렉트 수동 처리)
            final_response = await self._follow_safe_redirects_async(url)
            
            # 4. 응답 검증
            if not self._validate_response_headers(final_response):
                return {
                    'success': False,
                    'error': '허용되지 않는 응답 형식',
                    'base_url': str(final_response.url)
                }
            
            # 5. HTTP 상태 코드 검사
            if final_response.status >= 400:
                return {
                    'success': False,
                    'error': f'HTTP {final_response.status} 오류',
                    'base_url': str(final_response.url),
                    'status_code': final_response.status
                }
            
            # 6. 비동기 콘텐츠 읽기
            content = await self._read_content_safely_async(final_response)
            
            # 7. 인코딩 감지 및 텍스트 변환
            html_text = await self._decode_content_async(final_response, content)
            
            # 8. HTML 파싱
            soup = self._parse_html_with_fallback(html_text)
            
            logger.info(f"비동기 파싱 성공: {final_response.url} (상태코드: {final_response.status})")
            
            return {
                'success': True,
                'soup': soup,
                'base_url': str(final_response.url),
                'status_code': final_response.status,
                'headers': dict(final_response.headers),
                'content_type': final_response.headers.get('content-type', ''),
                'error': None
            }
            
        except asyncio.TimeoutError:
            error_msg = f"비동기 요청 타임아웃: {url}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg, 'base_url': url}
            
        except aiohttp.ClientError as e:
            error_msg = f"비동기 HTTP 클라이언트 오류: {url} - {str(e)}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg, 'base_url': url}
            
        except Exception as e:
            error_msg = f"예상치 못한 비동기 오류: {url} - {str(e)}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg, 'base_url': url}
    
    async def _follow_safe_redirects_async(self, url: str, max_redirects: int = 10) -> aiohttp.ClientResponse:
        """비동기 안전한 리다이렉트 추적"""
        redirect_count = 0
        current_url = url
        visited_urls = set()  # 리다이렉트 루프 방지
        
        while redirect_count < max_redirects:
            # 리다이렉트 루프 감지
            if current_url in visited_urls:
                raise Exception(f"리다이렉트 루프 감지: {current_url}")
            
            visited_urls.add(current_url)
            
            # 비동기 요청
            response = await self.session.get(current_url, allow_redirects=False)
            
            # 리다이렉트가 아니면 종료
            if not (300 <= response.status < 400):
                return response
            
            # Location 헤더 확인
            location = response.headers.get('Location')
            if not location:
                return response
            
            # 절대 URL로 변환
            next_url = str(response.url.join(aiohttp.URL(location)))
            
            # 리다이렉트 대상 URL 안전성 검증
            if not await self.ssrf_protection.is_safe_url(next_url):
                raise Exception(f"리다이렉트 대상이 안전하지 않음: {next_url}")
            
            logger.debug(f"비동기 안전한 리다이렉트: {current_url} -> {next_url}")
            
            current_url = next_url
            redirect_count += 1
            response.close()  # 이전 응답 정리
        
        raise Exception("리다이렉트 횟수 초과")
    
    def _validate_response_headers(self, response: aiohttp.ClientResponse) -> bool:
        """응답 헤더 검증"""
        # Content-Length 검증
        content_length = response.headers.get('content-length')
        if content_length:
            try:
                length = int(content_length)
                if length > self.max_content_length:
                    logger.warning(f"콘텐츠 크기가 너무 큼: {length} bytes")
                    return False
            except ValueError:
                pass
        
        # Content-Type 검증
        content_type = response.headers.get('content-type', '').lower()
        if not content_type:
            logger.warning("Content-Type 헤더가 없음")
            return False
        
        main_type = content_type.split(';')[0].strip()
        if main_type not in AsyncParserConstants.ALLOWED_CONTENT_TYPES:
            logger.warning(f"허용되지 않는 Content-Type: {content_type}")
            return False
        
        return True
    
    async def _read_content_safely_async(self, response: aiohttp.ClientResponse) -> bytes:
        """비동기로 안전하게 콘텐츠 읽기"""
        chunks = []
        total_size = 0
        
        async for chunk in response.content.iter_chunked(AsyncParserConstants.CHUNK_SIZE):
            chunks.append(chunk)
            total_size += len(chunk)
            
            if total_size > self.max_content_length:
                raise Exception(f"콘텐츠 크기 한계 초과: {total_size} bytes")
        
        return b''.join(chunks)
    
    async def _decode_content_async(self, response: aiohttp.ClientResponse, content: bytes) -> str:
        """비동기 인코딩 감지 및 디코딩"""
        # 1. aiohttp 자동 감지 사용
        try:
            return await response.text()
        except Exception:
            pass
        
        # 2. 수동 디코딩
        encoding = 'utf-8'
        
        # HTTP 헤더에서 인코딩 확인
        content_type = response.headers.get('content-type', '')
        if 'charset=' in content_type:
            try:
                encoding = content_type.split('charset=')[1].split(';')[0].strip()
            except:
                pass
        
        try:
            return content.decode(encoding, errors='ignore')
        except:
            return content.decode('utf-8', errors='ignore')
    
    async def parse_html_string(self, html_string: str, base_url: Optional[str] = None) -> Dict[str, Any]:
        """
        HTML 문자열을 직접 파싱 (비동기 버전)
        
        Args:
            html_string (str): HTML 문자열
            base_url (str, optional): 상대 URL 해석용 기준 URL
            
        Returns:
            Dict[str, Any]: 파싱 결과
        """
        try:
            if not html_string or not html_string.strip():
                return {
                    'success': False,
                    'error': '빈 HTML 문자열',
                    'base_url': base_url
                }
            
            # 크기 제한 검증
            if len(html_string.encode('utf-8')) > self.max_content_length:
                return {
                    'success': False,
                    'error': f'HTML 크기가 너무 큼: {len(html_string)} bytes',
                    'base_url': base_url
                }
            
            # HTML 파싱 (CPU 집약적이므로 executor에서 실행)
            loop = asyncio.get_event_loop()
            soup = await loop.run_in_executor(
                None, 
                self._parse_html_with_fallback, 
                html_string
            )
            
            logger.info("비동기 HTML 문자열 파싱 완료")
            
            return {
                'success': True,
                'soup': soup,
                'base_url': base_url,
                'error': None
            }
            
        except Exception as e:
            error_msg = f"비동기 HTML 파싱 오류: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg,
                'base_url': base_url
            }
    
    async def parse(self, html: str) -> BeautifulSoup:
        """
        프로젝트 요구사항에 맞는 비동기 파싱 함수
        
        Args:
            html (str): HTML 문자열
            
        Returns:
            BeautifulSoup: 파싱된 객체
            
        Raises:
            ValueError: 빈 HTML 입력 시
            Exception: 파싱 실패 시
        """
        if not html or not html.strip():
            raise ValueError("빈 HTML 입력")
        
        # CPU 집약적 작업을 executor에서 실행
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, 
            self._parse_html_with_fallback, 
            html
        )
    
    def _parse_html_with_fallback(self, html_string: str) -> BeautifulSoup:
        """여러 파서를 시도하여 HTML 파싱 (동기 버전)"""
        for parser in AsyncParserConstants.PARSERS:
            try:
                soup = BeautifulSoup(html_string, parser)
                logger.debug(f"파싱 성공 (파서: {parser})")
                return soup
            except Exception as e:
                logger.debug(f"{parser} 파서 실패: {str(e)}")
                continue
        
        # 모든 파서 실패 시 기본 파서로 재시도
        logger.warning("모든 파서 실패, html.parser로 강제 시도")
        return BeautifulSoup(html_string, 'html.parser')
    
    async def close(self):
        """비동기 세션 정리"""
        if not self._closed and self.session and not self.session.closed:
            await self.session.close()
            self._closed = True
    
    def __del__(self):
        """소멸자에서 세션 정리 시도"""
        if not self._closed and self.session and not self.session.closed:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self.close())
                else:
                    loop.run_until_complete(self.close())
            except:
                pass

# 비동기 편의 함수들
async def parse_url_async(url: str, 
                         timeout: int = AsyncParserConstants.DEFAULT_TIMEOUT, 
                         verify_ssl: bool = True) -> Dict[str, Any]:
    """비동기 URL 파싱 편의 함수"""
    async with AsyncHTMLParser(timeout=timeout, verify_ssl=verify_ssl) as parser:
        return await parser.parse_from_url(url)

async def parse_html_async(html_string: str, base_url: Optional[str] = None) -> Dict[str, Any]:
    """비동기 HTML 문자열 파싱 편의 함수"""
    async with AsyncHTMLParser() as parser:
        return await parser.parse_html_string(html_string, base_url)

async def parse_async(html: str) -> BeautifulSoup:
    """비동기 프로젝트 요구사항용 파싱 함수"""
    async with AsyncHTMLParser() as parser:
        return await parser.parse(html)

# 다중 URL 동시 처리 함수
async def parse_multiple_urls(urls: List[str], 
                            max_concurrent: int = 10,
                            timeout: int = AsyncParserConstants.DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    """
    여러 URL을 동시에 비동기 처리
    
    Args:
        urls (List[str]): URL 리스트
        max_concurrent (int): 최대 동시 처리 수
        timeout (int): 각 요청의 타임아웃
        
    Returns:
        List[Dict[str, Any]]: 각 URL의 파싱 결과
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def parse_single_url(url: str) -> Dict[str, Any]:
        async with semaphore:
            async with AsyncHTMLParser(timeout=timeout) as parser:
                return await parser.parse_from_url(url)
    
    tasks = [parse_single_url(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # 예외 처리
    processed_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            processed_results.append({
                'success': False,
                'error': f'비동기 처리 오류: {str(result)}',
                'base_url': urls[i]
            })
        else:
            processed_results.append(result)
    
    return processed_results

# 테스트 코드
if __name__ == "__main__":
    async def test_async_parser():
        print("=== 비동기 HTML Parser 테스트 ===")
        
        # 단일 URL 테스트
        print("\n1. 단일 URL 비동기 파싱:")
        result = await parse_url_async("https://httpbin.org/html")
        print(f"결과: {'성공' if result['success'] else '실패'}")
        if result['success']:
            print(f"제목: {result['soup'].title.string if result['soup'].title else 'None'}")
        
        # 다중 URL 동시 처리 테스트
        print("\n2. 다중 URL 동시 처리:")
        test_urls = [
            "https://httpbin.org/html",
            "https://httpbin.org/json",  # 차단되어야 함
            "https://example.com",
        ]
        
        results = await parse_multiple_urls(test_urls, max_concurrent=3)
        for i, result in enumerate(results):
            print(f"URL {i+1}: {'성공' if result['success'] else '실패'}")
            if not result['success']:
                print(f"  오류: {result['error']}")
    
    # 이벤트 루프 실행
    asyncio.run(test_async_parser())