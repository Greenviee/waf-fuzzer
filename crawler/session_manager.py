"""
세션 관리자
HTTP 세션, 쿠키, 인증 상태를 관리

담당: 팀 A - 인원 1 (크롤러 엔진 & 네트워크 담당)
"""

import aiohttp
import asyncio
import ssl
import base64
import re

from utils.logger import get_logger

logger = get_logger(__name__)


class AuthConfig:
    """인증 설정"""

    def __init__(
        self,
        auth_type="none",
        username=None,
        password=None,
        token=None,
        login_url=None,
        login_data=None,
        csrf_field=None,
        success_indicator=None
    ):
        """
        인증 설정 초기화

        Args:
            auth_type: 인증 방식 (none, basic, bearer, cookie, form)
            username: 사용자명
            password: 비밀번호
            token: Bearer 토큰
            login_url: 로그인 URL
            login_data: 로그인 폼 데이터
            csrf_field: CSRF 필드명
            success_indicator: 로그인 성공 확인용 문자열
        """
        self.auth_type = auth_type
        self.username = username
        self.password = password
        self.token = token
        self.login_url = login_url
        self.csrf_field = csrf_field
        self.success_indicator = success_indicator

        if login_data is None:
            self.login_data = {}
        else:
            self.login_data = login_data


class SessionManager:
    """
    HTTP 세션 관리자

    주요 기능:
    - 세션 쿠키 유지 (로그인 상태 유지)
    - 다양한 인증 방식 지원 (Basic, Bearer, Form)
    - 요청 재시도 로직
    - SSL 설정
    - 프록시 지원
    """

    # 기본 User-Agent
    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        auth_config=None,
        proxy=None,
        verify_ssl=False,
        user_agent=None
    ):
        """
        세션 관리자 초기화

        Args:
            auth_config: 인증 설정 (AuthConfig 객체)
            proxy: 프록시 서버 URL (예: http://127.0.0.1:8080)
            verify_ssl: SSL 인증서 검증 여부
            user_agent: 커스텀 User-Agent
        """
        if auth_config is None:
            self.auth_config = AuthConfig()
        else:
            self.auth_config = auth_config

        self.proxy = proxy
        self.verify_ssl = verify_ssl

        # 세션 객체
        self._session = None

        # 쿠키 저장소
        self._cookies = {}

        # 기본 헤더
        if user_agent is None:
            ua = self.DEFAULT_USER_AGENT
        else:
            ua = user_agent

        self._headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

        # 인증 상태
        self._is_authenticated = False

        logger.debug("세션 관리자 초기화 완료")

    async def create_session(self):
        """
        새 HTTP 세션 생성

        Returns:
            aiohttp.ClientSession 인스턴스
        """
        # 기존 세션이 있고 열려있으면 반환
        if self._session is not None and not self._session.closed:
            return self._session

        # SSL 컨텍스트 설정
        ssl_context = None
        if not self.verify_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        # 타임아웃 설정
        timeout = aiohttp.ClientTimeout(
            total=30,
            connect=10,
            sock_read=10
        )

        # TCP 커넥터 설정
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=100,
            limit_per_host=10,
            ttl_dns_cache=300
        )

        # 쿠키 저장소
        cookie_jar = aiohttp.CookieJar(unsafe=True)

        # 세션 생성
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self._headers,
            cookie_jar=cookie_jar
        )

        logger.info("HTTP 세션 생성 완료")

        # 인증 처리
        if self.auth_config.auth_type != "none":
            await self._authenticate()

        return self._session

    async def _authenticate(self):
        """인증 수행"""
        auth_type = self.auth_config.auth_type

        try:
            if auth_type == "basic":
                self._basic_auth()
            elif auth_type == "bearer":
                self._bearer_auth()
            elif auth_type == "form":
                await self._form_login()
            elif auth_type == "cookie":
                self._cookie_auth()

            self._is_authenticated = True
            logger.info("인증 완료 (방식: %s)", auth_type)

        except Exception as e:
            logger.error("인증 실패: %s", e)
            self._is_authenticated = False

    def _basic_auth(self):
        """HTTP Basic 인증"""
        if self.auth_config.username and self.auth_config.password:
            credentials = self.auth_config.username + ":" + self.auth_config.password
            encoded = base64.b64encode(credentials.encode()).decode()
            self._headers["Authorization"] = "Basic " + encoded

    def _bearer_auth(self):
        """Bearer 토큰 인증"""
        if self.auth_config.token:
            self._headers["Authorization"] = "Bearer " + self.auth_config.token

    def _cookie_auth(self):
        """쿠키 기반 인증 (미리 설정된 쿠키 사용)"""
        # 외부에서 set_cookie()로 설정된 쿠키 사용
        pass

    async def _form_login(self):
        """폼 기반 로그인"""
        if not self.auth_config.login_url:
            logger.warning("로그인 URL이 설정되지 않음")
            return

        login_data = self.auth_config.login_data.copy()

        # CSRF 토큰 처리
        if self.auth_config.csrf_field:
            csrf_token = await self._extract_csrf_token(
                self.auth_config.login_url,
                self.auth_config.csrf_field
            )
            if csrf_token:
                login_data[self.auth_config.csrf_field] = csrf_token
                logger.debug("CSRF 토큰 추출 완료")

        # 로그인 요청
        try:
            async with self._session.post(
                self.auth_config.login_url,
                data=login_data,
                allow_redirects=True
            ) as response:
                response_text = await response.text()

                # 로그인 성공 확인
                if self.auth_config.success_indicator:
                    if self.auth_config.success_indicator in response_text:
                        logger.info("폼 로그인 성공")
                    else:
                        logger.warning("폼 로그인 실패 (성공 지시자 없음)")
                elif response.status == 200:
                    logger.info("폼 로그인 완료 (상태 코드: 200)")
                else:
                    logger.warning("폼 로그인 응답: %d", response.status)

        except Exception as e:
            logger.error("폼 로그인 오류: %s", e)

    async def _extract_csrf_token(self, url, field_name):
        """
        페이지에서 CSRF 토큰 추출

        Args:
            url: 토큰이 있는 페이지 URL
            field_name: CSRF 필드 이름

        Returns:
            CSRF 토큰 값 또는 None
        """
        try:
            async with self._session.get(url) as response:
                html = await response.text()

                # input 태그에서 추출
                patterns = [
                    r'name=["\']?' + field_name + r'["\']?\s+value=["\']?([^"\'>\s]+)',
                    r'value=["\']?([^"\'>\s]+)["\']?\s+name=["\']?' + field_name,
                    r'name="' + field_name + r'"[^>]*value="([^"]+)"',
                    r"name='" + field_name + r"'[^>]*value='([^']+)'",
                ]

                for pattern in patterns:
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match:
                        return match.group(1)

                # meta 태그에서 추출
                meta_pattern = r'<meta[^>]*name=["\']?' + field_name + r'["\']?[^>]*content=["\']?([^"\']+)'
                match = re.search(meta_pattern, html, re.IGNORECASE)
                if match:
                    return match.group(1)

        except Exception as e:
            logger.warning("CSRF 토큰 추출 실패: %s", e)

        return None

    async def get(
        self,
        url,
        timeout=10,
        allow_redirects=True,
        headers=None,
        **kwargs
    ):
        """
        GET 요청

        Args:
            url: 요청 URL
            timeout: 타임아웃 (초)
            allow_redirects: 리다이렉트 허용 여부
            headers: 추가 헤더

        Returns:
            응답 딕셔너리 또는 None
        """
        return await self._request(
            method="GET",
            url=url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            headers=headers,
            **kwargs
        )

    async def post(
        self,
        url,
        data=None,
        json_data=None,
        timeout=10,
        allow_redirects=True,
        headers=None,
        **kwargs
    ):
        """
        POST 요청

        Args:
            url: 요청 URL
            data: Form 데이터
            json_data: JSON 데이터
            timeout: 타임아웃 (초)
            allow_redirects: 리다이렉트 허용 여부
            headers: 추가 헤더

        Returns:
            응답 딕셔너리 또는 None
        """
        return await self._request(
            method="POST",
            url=url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            headers=headers,
            data=data,
            json=json_data,
            **kwargs
        )

    async def _request(
        self,
        method,
        url,
        timeout=10,
        allow_redirects=True,
        max_retries=3,
        headers=None,
        **kwargs
    ):
        """
        HTTP 요청 수행 (재시도 로직 포함)

        Args:
            method: HTTP 메서드
            url: 요청 URL
            timeout: 타임아웃 (초)
            allow_redirects: 리다이렉트 허용
            max_retries: 최대 재시도 횟수
            headers: 추가 헤더

        Returns:
            응답 정보 딕셔너리 또는 None
        """
        if self._session is None:
            await self.create_session()

        # 타임아웃 설정
        request_timeout = aiohttp.ClientTimeout(total=timeout)

        # 헤더 병합
        request_headers = self._headers.copy()
        if headers is not None:
            request_headers.update(headers)

        # 재시도 로직
        for attempt in range(max_retries):
            try:
                async with self._session.request(
                    method=method,
                    url=url,
                    timeout=request_timeout,
                    allow_redirects=allow_redirects,
                    headers=request_headers,
                    proxy=self.proxy,
                    **kwargs
                ) as response:
                    # 응답 텍스트 읽기
                    try:
                        text = await response.text()
                    except Exception:
                        text = ""

                    # 쿠키 저장
                    for cookie in response.cookies.values():
                        self._cookies[cookie.key] = cookie.value

                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "cookies": dict(response.cookies),
                        "url": str(response.url),
                        "text": text,
                        "content_type": response.content_type,
                        "method": method
                    }

            except asyncio.TimeoutError:
                logger.warning(
                    "요청 타임아웃 (시도 %d/%d): %s",
                    attempt + 1, max_retries, url
                )
            except aiohttp.ClientError as e:
                logger.warning(
                    "요청 실패 (시도 %d/%d): %s",
                    attempt + 1, max_retries, e
                )
            except Exception as e:
                logger.error("예상치 못한 오류: %s", e)
                break

            # 재시도 전 대기 (지수 백오프)
            if attempt < max_retries - 1:
                wait_time = (2 ** attempt) * 0.5
                await asyncio.sleep(wait_time)

        return None

    def set_cookie(self, name, value):
        """
        쿠키 설정

        Args:
            name: 쿠키 이름
            value: 쿠키 값
        """
        self._cookies[name] = value
        if self._session is not None:
            self._session.cookie_jar.update_cookies({name: value})
        logger.debug("쿠키 설정: %s", name)

    def set_cookies(self, cookies):
        """
        여러 쿠키 한번에 설정

        Args:
            cookies: 쿠키 딕셔너리
        """
        for name, value in cookies.items():
            self.set_cookie(name, value)

    def set_header(self, name, value):
        """
        헤더 설정

        Args:
            name: 헤더 이름
            value: 헤더 값
        """
        self._headers[name] = value
        logger.debug("헤더 설정: %s", name)

    def get_cookies(self):
        """현재 쿠키 반환"""
        return self._cookies.copy()

    def get_headers(self):
        """현재 헤더 반환"""
        return self._headers.copy()

    @property
    def is_authenticated(self):
        """인증 상태"""
        return self._is_authenticated

    async def close(self):
        """세션 종료"""
        if self._session is not None and not self._session.closed:
            await self._session.close()
            self._session = None
            logger.info("HTTP 세션 종료")