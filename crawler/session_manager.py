# crawler/session_manager.py

import asyncio
import json
import re
from typing import Optional
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup

from utils.logger import get_logger

logger = get_logger(__name__)


class AuthConfig:
    """인증 설정"""

    # ... (기존 코드와 동일하므로 생략하지 않고 모두 포함합니다) ...
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

    # ✨ [개선 1 & 2] proxy 외에 verify_ssl, custom_headers 파라미터 추가
    def __init__(self, proxy=None, verify_ssl=False, custom_headers=None):
        """
        세션 매니저 초기화

        Args:
            proxy: 프록시 서버 URL (예: "http://127.0.0.1:8080")
            verify_ssl: SSL 인증서 검증 여부 (기본값: False)
            custom_headers: 커스텀 HTTP 헤더 딕셔너리
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

        # ✨ [개선 2] 커스텀 헤더가 제공되었다면 기본 헤더에 덮어쓰기 (WAF 우회용)
        if custom_headers:
            self._headers.update(custom_headers)

        self.proxy = proxy
        self.verify_ssl = verify_ssl  # ✨ [개선 1] 인스턴스 변수로 저장
        self._authenticated = False

    async def create_session(self):
        """세션 생성"""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=10,
                limit_per_host=5,
                ssl=self.verify_ssl  # ✨ [개선 1] 하드코딩 제거 및 변수 적용
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

    # ... (이하 _extract_csrf_token 부터 _request, get, post 등의 메서드는 완벽하므로 기존 코드 그대로 유지) ...
    @staticmethod
    def _extract_csrf_token(html: str, token_name: str) -> Optional[str]:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            token_input = soup.find('input', {'name': token_name})
            if token_input and token_input.get('value'):
                return token_input.get('value')
            common_names = [
                'user_token', 'csrf_token', '_token', 'token',
                'csrf', '_csrf_token', 'authenticity_token', '_csrf',
            ]
            for name in common_names:
                token_input = soup.find('input', {'name': name})
                if token_input and token_input.get('value'):
                    return token_input.get('value')
            hidden_inputs = soup.find_all('input', {'type': 'hidden'})
            for inp in hidden_inputs:
                name = inp.get('name', '').lower()
                if 'token' in name or 'csrf' in name:
                    value = inp.get('value')
                    if value:
                        return value
        except Exception as e:
            logger.warning("CSRF 토큰 추출 실패: %s", e)
        return None

    @staticmethod
    def _extract_meta_redirect(html: str, base_url: str) -> Optional[str]:
        try:
            match = re.search(
                r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?\d+;?\s*url=([^"\'\s>]+)',
                html,
                re.IGNORECASE
            )
            if match:
                redirect_url = match.group(1)
                if not redirect_url.startswith('http'):
                    redirect_url = urljoin(base_url, redirect_url)
                return redirect_url
        except Exception as e:
            logger.debug("메타 리다이렉트 추출 실패: %s", e)
        return None

    async def login(self, auth_config: AuthConfig) -> bool:
        if self._session is None:
            await self.create_session()

        logger.info("로그인 시도: %s", auth_config.login_url)
        login_page = await self.get(auth_config.login_url)

        if not login_page:
            return False

        html = login_page.get("text", "")
        csrf_token = None
        if auth_config.csrf_token_name:
            csrf_token = self._extract_csrf_token(html, auth_config.csrf_token_name)

        login_data = {
            auth_config.username_field: auth_config.username,
            auth_config.password_field: auth_config.password,
        }

        if auth_config.submit_field:
            login_data[auth_config.submit_field] = auth_config.submit_field

        if csrf_token and auth_config.csrf_token_name:
            login_data[auth_config.csrf_token_name] = csrf_token

        login_data.update(auth_config.extra_fields)

        response = await self.post(
            auth_config.login_url,
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if not response:
            return False

        text = response.get("text", "")
        final_url = response.get("url", "")

        redirect_url = self._extract_meta_redirect(text, auth_config.login_url)
        if redirect_url:
            response = await self.get(redirect_url)
            if response:
                text = response.get("text", "")
                final_url = response.get("url", "")

        if auth_config.failure_indicator and auth_config.failure_indicator in text:
            return False

        if auth_config.success_indicator:
            if auth_config.success_indicator in text or auth_config.success_indicator.lower() in text.lower():
                self._authenticated = True
                return True

        if 'login' not in final_url.lower():
            self._authenticated = True
            return True

        if response and response.get("status") in [200, 302]:
            self._authenticated = True
            return True

        return False

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    def get_cookies(self) -> dict:
        cookies = {}
        cookies.update(self._cookies)
        if self._session and self._session.cookie_jar:
            for cookie in self._session.cookie_jar:
                cookies[cookie.key] = cookie.value
        return cookies

    def set_cookies(self, cookies: dict):
        if cookies:
            self._cookies.update(cookies)

    def set_header(self, name: str, value: str):
        self._headers[name] = value

    def set_headers(self, headers: dict):
        if headers:
            self._headers.update(headers)

    @staticmethod
    def is_api_content_type(content_type: Optional[str]) -> bool:
        if not content_type:
            return False
        api_types = ['application/json', 'application/xml', 'application/x-www-form-urlencoded', 'text/json',
                     'text/xml']
        content_type = content_type.lower()
        return any(api_type in content_type for api_type in api_types)

    async def _request(self, method: str, url: str, timeout: int = 10, allow_redirects: bool = True,
                       max_retries: int = 3, headers: Optional[dict] = None, **kwargs) -> Optional[dict]:
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
                    except Exception:
                        text = ""

                    for cookie in response.cookies.values():
                        self._cookies[cookie.key] = cookie.value

                    response_cookies = {cookie.key: cookie.value for cookie in response.cookies.values()}

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
                pass
            except aiohttp.ClientError:
                pass
            except Exception:
                break

            if attempt < max_retries - 1:
                await asyncio.sleep((2 ** attempt) * 0.5)

        return None

    async def get(self, url: str, **kwargs) -> Optional[dict]:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, data: Optional[dict] = None, json_data: Optional[dict] = None,
                   headers: Optional[dict] = None, **kwargs) -> Optional[dict]:
        if json_data is not None:
            return await self._request("POST", url, json=json_data, headers=headers, **kwargs)
        return await self._request("POST", url, data=data, headers=headers, **kwargs)

    async def put(self, url: str, data: Optional[dict] = None, json_data: Optional[dict] = None,
                  headers: Optional[dict] = None, **kwargs) -> Optional[dict]:
        if json_data is not None:
            return await self._request("PUT", url, json=json_data, headers=headers, **kwargs)
        return await self._request("PUT", url, data=data, headers=headers, **kwargs)

    async def delete(self, url: str, **kwargs) -> Optional[dict]:
        return await self._request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> Optional[dict]:
        return await self._request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> Optional[dict]:
        return await self._request("OPTIONS", url, **kwargs)

    async def detect_methods(self, url: str) -> list:
        allowed_methods = []
        try:
            response = await self.options(url, max_retries=1, timeout=5)
            if response:
                allow_header = response.get("headers", {}).get("Allow", "")
                if allow_header:
                    return [m.strip().upper() for m in allow_header.split(",")]
                cors_header = response.get("headers", {}).get("Access-Control-Allow-Methods", "")
                if cors_header:
                    return [m.strip().upper() for m in cors_header.split(",")]
        except Exception:
            pass

        test_methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]
        for method in test_methods:
            try:
                response = await self._request(method=method, url=url, max_retries=1, timeout=3, allow_redirects=False)
                if response and response.get("status", 0) != 405:
                    allowed_methods.append(method)
            except Exception:
                continue
        return allowed_methods if allowed_methods else ["GET"]