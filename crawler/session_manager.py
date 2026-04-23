# crawler/session_manager.py

import asyncio
import json
from typing import Optional

import aiohttp
from bs4 import BeautifulSoup

from utils.logger import get_logger

logger = get_logger(__name__)


class AuthConfig:
    """인증 설정"""

    def __init__(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        extra_fields: Optional[dict] = None,
        success_indicator: Optional[str] = None,
        failure_indicator: Optional[str] = None,
        csrf_token_name: Optional[str] = "user_token",
        submit_field: Optional[str] = "Login"
    ):
        """
        인증 설정 초기화

        Args:
            login_url: 로그인 URL
            username: 사용자명
            password: 비밀번호
            username_field: 사용자명 폼 필드명
            password_field: 비밀번호 폼 필드명
            extra_fields: 추가 폼 필드
            success_indicator: 로그인 성공 시 나타나는 문자열
            failure_indicator: 로그인 실패 시 나타나는 문자열
            csrf_token_name: CSRF 토큰 필드명 (None이면 자동 감지)
            submit_field: Submit 버튼 필드명
        """
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.extra_fields = extra_fields or {}
        self.success_indicator = success_indicator
        self.failure_indicator = failure_indicator
        self.csrf_token_name = csrf_token_name
        self.submit_field = submit_field


class SessionManager:
    """HTTP 세션 관리자"""

    def __init__(self, proxy=None):
        """
        세션 매니저 초기화

        Args:
            proxy: 프록시 서버 URL (예: "http://127.0.0.1:8080")
        """
        self._session = None
        self._cookies = {}
        self._headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        self.proxy = proxy
        self._authenticated = False

    async def create_session(self):
        """세션 생성"""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=10,
                limit_per_host=5,
                ssl=False
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                cookie_jar=aiohttp.CookieJar(unsafe=True)
            )
            logger.debug("새 세션 생성됨")

    async def close(self):
        """세션 종료"""
        if self._session and not self._session.closed:
            await self._session.close()
            self._authenticated = False
            logger.debug("세션 종료됨")

    @staticmethod
    def _extract_csrf_token(html: str, token_name: str) -> Optional[str]:
        """
        HTML에서 CSRF 토큰 추출

        Args:
            html: HTML 텍스트
            token_name: 토큰 필드명

        Returns:
            str or None: 토큰 값
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')

            # 1. 지정된 이름으로 찾기
            token_input = soup.find('input', {'name': token_name})
            if token_input and token_input.get('value'):
                return token_input.get('value')

            # 2. 일반적인 CSRF 토큰 이름들로 찾기
            common_names = [
                'user_token',
                'csrf_token',
                '_token',
                'token',
                'csrf',
                '_csrf_token',
                'authenticity_token',
                '_csrf',
            ]

            for name in common_names:
                token_input = soup.find('input', {'name': name})
                if token_input and token_input.get('value'):
                    logger.debug("CSRF 토큰 발견: %s", name)
                    return token_input.get('value')

            # 3. hidden 필드 중 token이 포함된 것 찾기
            hidden_inputs = soup.find_all('input', {'type': 'hidden'})
            for inp in hidden_inputs:
                name = inp.get('name', '').lower()
                if 'token' in name or 'csrf' in name:
                    value = inp.get('value')
                    if value:
                        logger.debug("CSRF 토큰 발견 (hidden): %s", inp.get('name'))
                        return value

        except Exception as e:
            logger.warning("CSRF 토큰 추출 실패: %s", e)

        return None

    async def login(self, auth_config: AuthConfig) -> bool:
        """
        로그인 수행 (CSRF 토큰 자동 처리)

        Args:
            auth_config: AuthConfig 인스턴스

        Returns:
            bool: 로그인 성공 여부
        """
        if self._session is None:
            await self.create_session()

        logger.info("로그인 시도: %s", auth_config.login_url)

        # ============================================================
        # 1단계: 로그인 페이지에서 CSRF 토큰 추출
        # ============================================================
        login_page = await self.get(auth_config.login_url)

        if not login_page:
            logger.error("로그인 페이지 접근 실패")
            return False

        html = login_page.get("text", "")

        # CSRF 토큰 추출
        csrf_token = None
        if auth_config.csrf_token_name:
            csrf_token = self._extract_csrf_token(html, auth_config.csrf_token_name)
            if csrf_token:
                logger.debug("CSRF 토큰 추출 성공: %s...", csrf_token[:20])
            else:
                logger.debug("CSRF 토큰 없음 (필요 없을 수 있음)")

        # ============================================================
        # 2단계: 로그인 데이터 구성
        # ============================================================
        login_data = {
            auth_config.username_field: auth_config.username,
            auth_config.password_field: auth_config.password,
        }

        # Submit 버튼 필드 추가
        if auth_config.submit_field:
            login_data[auth_config.submit_field] = auth_config.submit_field

        # CSRF 토큰 추가
        if csrf_token and auth_config.csrf_token_name:
            login_data[auth_config.csrf_token_name] = csrf_token

        # 추가 필드
        login_data.update(auth_config.extra_fields)

        logger.debug(
            "로그인 데이터: %s",
            {k: v if 'pass' not in k.lower() else '***' for k, v in login_data.items()}
        )

        # ============================================================
        # 3단계: 로그인 요청
        # ============================================================
        response = await self.post(auth_config.login_url, data=login_data)

        if not response:
            logger.error("로그인 요청 실패")
            return False

        text = response.get("text", "")
        final_url = response.get("url", "")

        logger.debug("로그인 후 URL: %s", final_url)

        # ============================================================
        # 4단계: 로그인 결과 확인
        # ============================================================

        # 실패 지시자 확인
        if auth_config.failure_indicator and auth_config.failure_indicator in text:
            logger.error(
                "로그인 실패: 실패 지시자 발견 ('%s')",
                auth_config.failure_indicator
            )
            return False

        # 성공 지시자 확인
        if auth_config.success_indicator:
            if auth_config.success_indicator in text:
                self._authenticated = True
                logger.info("로그인 성공")
                return True

            # 대소문자 무시하고 확인
            if auth_config.success_indicator.lower() in text.lower():
                self._authenticated = True
                logger.info("로그인 성공 (대소문자 무시)")
                return True

            logger.error(
                "로그인 실패: 성공 지시자 없음 ('%s')",
                auth_config.success_indicator
            )
            logger.debug("응답 내용 (처음 500자): %s", text[:500])
            return False

        # 성공 지시자가 없으면 URL 또는 상태 코드로 판단
        if 'login' not in final_url.lower():
            self._authenticated = True
            logger.info("로그인 성공 (URL 기반 판단)")
            return True

        if response.get("status") in [200, 302]:
            self._authenticated = True
            logger.info("로그인 성공 (상태 코드 기반)")
            return True

        return False

    @property
    def is_authenticated(self) -> bool:
        """인증 여부 확인"""
        return self._authenticated

    def get_cookies(self) -> dict:
        """
        현재 세션의 모든 쿠키 반환

        Returns:
            dict: 쿠키 딕셔너리 {name: value}
        """
        cookies = {}
        cookies.update(self._cookies)

        if self._session and self._session.cookie_jar:
            for cookie in self._session.cookie_jar:
                cookies[cookie.key] = cookie.value

        return cookies

    def set_cookies(self, cookies: dict):
        """
        쿠키 설정

        Args:
            cookies: 쿠키 딕셔너리 {name: value}
        """
        if cookies:
            self._cookies.update(cookies)
            logger.debug("쿠키 설정됨: %d개", len(cookies))

    def set_header(self, name: str, value: str):
        """
        헤더 설정

        Args:
            name: 헤더 이름
            value: 헤더 값
        """
        self._headers[name] = value

    def set_headers(self, headers: dict):
        """
        여러 헤더 설정

        Args:
            headers: 헤더 딕셔너리
        """
        if headers:
            self._headers.update(headers)

    @staticmethod
    def is_api_content_type(content_type: Optional[str]) -> bool:
        """
        API 콘텐츠 타입인지 확인

        Args:
            content_type: Content-Type 헤더 값

        Returns:
            bool: API 콘텐츠 타입 여부
        """
        if not content_type:
            return False

        api_types = [
            'application/json',
            'application/xml',
            'application/x-www-form-urlencoded',
            'text/json',
            'text/xml'
        ]

        content_type = content_type.lower()
        return any(api_type in content_type for api_type in api_types)

    async def _request(
            self,
            method: str,
            url: str,
            timeout: int = 10,
            allow_redirects: bool = True,
            max_retries: int = 3,
            headers: Optional[dict] = None,
            **kwargs
    ) -> Optional[dict]:
        """
        HTTP 요청 수행 (재시도 로직 포함)

        Args:
            method: HTTP 메서드
            url: 요청 URL
            timeout: 타임아웃 (초)
            allow_redirects: 리다이렉트 허용 여부
            max_retries: 최대 재시도 횟수
            headers: 추가 헤더
            **kwargs: 추가 요청 옵션

        Returns:
            dict or None: 응답 데이터 또는 None
        """
        if self._session is None:
            await self.create_session()

        request_timeout = aiohttp.ClientTimeout(total=timeout)

        request_headers = self._headers.copy()
        if headers is not None:
            request_headers.update(headers)

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
                    json_data = None

                    try:
                        content_type = response.content_type

                        if self.is_api_content_type(content_type):
                            try:
                                json_data = await response.json()
                                text = json.dumps(json_data, ensure_ascii=False)
                            except json.JSONDecodeError:
                                text = await response.text()
                        else:
                            text = await response.text()

                    except UnicodeDecodeError:
                        text = ""
                        logger.debug("텍스트 디코딩 실패 (바이너리 데이터)")
                    except Exception as e:
                        text = ""
                        logger.debug("응답 읽기 오류: %s", e)

                    for cookie in response.cookies.values():
                        self._cookies[cookie.key] = cookie.value

                    response_cookies = {
                        cookie.key: cookie.value
                        for cookie in response.cookies.values()
                    }

                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "cookies": response_cookies,
                        "url": str(response.url),
                        "text": text,
                        "json": json_data,
                        "content_type": response.content_type,
                        "method": method,
                        "history": [str(r.url) for r in response.history]
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

            if attempt < max_retries - 1:
                await asyncio.sleep((2 ** attempt) * 0.5)

        return None

    async def get(self, url: str, **kwargs) -> Optional[dict]:
        """GET 요청"""
        return await self._request("GET", url, **kwargs)

    async def post(
            self,
            url: str,
            data: Optional[dict] = None,
            json_data: Optional[dict] = None,
            **kwargs
    ) -> Optional[dict]:
        """POST 요청"""
        if json_data is not None:
            return await self._request("POST", url, json=json_data, **kwargs)
        return await self._request("POST", url, data=data, **kwargs)

    async def put(
            self,
            url: str,
            data: Optional[dict] = None,
            json_data: Optional[dict] = None,
            **kwargs
    ) -> Optional[dict]:
        """PUT 요청"""
        if json_data is not None:
            return await self._request("PUT", url, json=json_data, **kwargs)
        return await self._request("PUT", url, data=data, **kwargs)

    async def delete(self, url: str, **kwargs) -> Optional[dict]:
        """DELETE 요청"""
        return await self._request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> Optional[dict]:
        """HEAD 요청"""
        return await self._request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> Optional[dict]:
        """OPTIONS 요청"""
        return await self._request("OPTIONS", url, **kwargs)

    async def detect_methods(self, url: str) -> list:
        """
        URL에서 지원하는 HTTP 메서드 감지

        Args:
            url: 대상 URL

        Returns:
            list: 지원하는 HTTP 메서드 목록
        """
        allowed_methods = []

        try:
            response = await self.options(url, max_retries=1, timeout=5)
            if response:
                allow_header = response.get("headers", {}).get("Allow", "")
                if allow_header:
                    methods = [m.strip().upper() for m in allow_header.split(",")]
                    return methods

                cors_header = response.get("headers", {}).get(
                    "Access-Control-Allow-Methods", ""
                )
                if cors_header:
                    methods = [m.strip().upper() for m in cors_header.split(",")]
                    return methods
        except Exception:
            pass

        test_methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]

        for method in test_methods:
            try:
                response = await self._request(
                    method=method,
                    url=url,
                    max_retries=1,
                    timeout=3,
                    allow_redirects=False
                )
                if response:
                    status = response.get("status", 0)
                    if status != 405:
                        allowed_methods.append(method)
            except Exception:
                continue

        return allowed_methods if allowed_methods else ["GET"]