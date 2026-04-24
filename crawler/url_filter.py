# crawler/url_filter.py

"""
URL 필터
크롤링 대상 URL을 필터링하고 정규화
"""

import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, unquote

from utils.logger import get_logger

logger = get_logger(__name__)


class URLFilter:
    """
    URL 필터링 및 정규화

    주요 기능:
    - 허용된 도메인만 크롤링
    - 파일 확장자 필터링 (이미지, CSS, JS 등 제외)
    - URL 정규화 (중복 방지)
    - 위험한 URL 패턴 제외 (logout, delete 등)
    - API 엔드포인트 감지
    """

    # 제외할 파일 확장자
    EXCLUDED_EXTENSIONS = {
        # 이미지
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp',
        # 스타일/스크립트
        '.css', '.js', '.map',
        # 폰트
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        # 문서
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        # 압축
        '.zip', '.rar', '.tar', '.gz', '.7z',
        # 미디어
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
        # 실행 파일
        '.exe', '.dll', '.so', '.dmg', '.apk'
    }

    # 기본 제외 패턴 (위험한 동작)
    DEFAULT_EXCLUDED_PATTERNS = [
        r'/logout',
        r'/signout',
        r'/sign-out',
        r'/log-out',
        r'/delete',
        r'/remove',
        r'/unsubscribe',
        r'/deactivate',
        r'\?.*logout',
        r'\?.*delete',
        r'\?.*remove',
    ]

    # API 엔드포인트 패턴
    API_PATTERNS = [
        r'/api/',
        r'/v\d+/',
        r'/graphql',
        r'/rest/',
        r'/ajax/',
        r'/json/',
        r'/xml/',
        r'\.json$',
        r'\.xml$',
    ]

    # 흥미로운 경로 패턴 (공격 표면 가능성 높음)
    INTERESTING_PATTERNS = [
        r'/admin',
        r'/login',
        r'/register',
        r'/signup',
        r'/upload',
        r'/download',
        r'/search',
        r'/user',
        r'/profile',
        r'/account',
        r'/settings',
        r'/config',
        r'/edit',
        r'/update',
        r'/create',
        r'/add',
        r'/submit',
        r'/process',
        r'/callback',
        r'/webhook',
        r'/redirect',
    ]

    def __init__(
            self,
            allowed_domains=None,
            excluded_patterns=None,
            max_url_length=2048
    ):
        """
        URL 필터 초기화

        Args:
            allowed_domains: 허용할 도메인 목록
            excluded_patterns: 제외할 URL 패턴 (정규식)
            max_url_length: 최대 URL 길이
        """
        if allowed_domains is None:
            self.allowed_domains = set()
        else:
            self.allowed_domains = set(allowed_domains)

        self.excluded_domains = set()
        self.max_url_length = max_url_length
        self.allowed_schemes = {'http', 'https'}

        # 제외 패턴 컴파일
        patterns = self.DEFAULT_EXCLUDED_PATTERNS.copy()
        if excluded_patterns is not None:
            patterns.extend(excluded_patterns)

        self._excluded_regex = []
        for pattern in patterns:
            compiled = re.compile(pattern, re.IGNORECASE)
            self._excluded_regex.append(compiled)

        # API 패턴 컴파일
        self._api_regex = []
        for pattern in self.API_PATTERNS:
            compiled = re.compile(pattern, re.IGNORECASE)
            self._api_regex.append(compiled)

        # 흥미로운 패턴 컴파일
        self._interesting_regex = []
        for pattern in self.INTERESTING_PATTERNS:
            compiled = re.compile(pattern, re.IGNORECASE)
            self._interesting_regex.append(compiled)

        logger.debug("URL 필터 초기화: 허용 도메인=%s", self.allowed_domains)

    def should_crawl(self, url):
        """
        URL을 크롤링해야 하는지 결정

        Args:
            url: 검사할 URL

        Returns:
            bool: 크롤링 여부
        """
        try:
            parsed = urlparse(url)

            if parsed.scheme not in self.allowed_schemes:
                logger.debug("스킴 불허: %s", url)
                return False

            if len(url) > self.max_url_length:
                logger.debug("URL 너무 김: %s...", url[:50])
                return False

            if not self._is_domain_allowed(parsed.netloc):
                logger.debug("도메인 불허: %s", parsed.netloc)
                return False

            if self._has_excluded_extension(parsed.path):
                logger.debug("확장자 제외: %s", url)
                return False

            if self._matches_excluded_pattern(url):
                logger.debug("패턴 제외: %s", url)
                return False

            return True

        except Exception as e:
            logger.warning("URL 필터링 오류 (%s): %s", url, e)
            return False

    def _is_domain_allowed(self, domain):
        """도메인 허용 여부 확인"""
        if domain in self.excluded_domains:
            return False

        if self.allowed_domains:
            for allowed in self.allowed_domains:
                if domain == allowed:
                    return True
                if domain.endswith('.' + allowed):
                    return True
            return False

        return True

    def _has_excluded_extension(self, path):
        """제외 확장자 여부 확인"""
        path_lower = path.lower()
        for ext in self.EXCLUDED_EXTENSIONS:
            if path_lower.endswith(ext):
                return True
        return False

    def _matches_excluded_pattern(self, url):
        """제외 패턴 매칭 여부"""
        for regex in self._excluded_regex:
            if regex.search(url):
                return True
        return False

    @staticmethod
    def normalize_url(url):
        """
        URL 정규화 (중복 방지용)

        Args:
            url: 원본 URL

        Returns:
            str: 정규화된 URL
        """
        try:
            parsed = urlparse(url)

            scheme = parsed.scheme.lower()

            netloc = parsed.netloc.lower()
            if ':80' in netloc and scheme == 'http':
                netloc = netloc.replace(':80', '')
            elif ':443' in netloc and scheme == 'https':
                netloc = netloc.replace(':443', '')

            path = parsed.path
            if not path:
                path = '/'
            path = re.sub(r'/+', '/', path)
            path = unquote(path)

            query = ''
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                sorted_params = sorted(params.items())
                query_list = []
                for k, v in sorted_params:
                    if len(v) == 1:
                        query_list.append((k, v[0]))
                    else:
                        query_list.append((k, v))
                query = urlencode(query_list, doseq=True)

            normalized = urlunparse((scheme, netloc, path, '', query, ''))

            return normalized

        except Exception as e:
            logger.warning("URL 정규화 실패 (%s): %s", url, e)
            return url

    def is_api_endpoint(self, url):
        """
        API 엔드포인트 여부 확인

        Args:
            url: 검사할 URL

        Returns:
            bool: API 엔드포인트 여부
        """
        for regex in self._api_regex:
            if regex.search(url):
                return True
        return False

    def is_interesting_url(self, url):
        """
        흥미로운 URL 여부 확인

        Args:
            url: 검사할 URL

        Returns:
            bool: 흥미로운 URL 여부
        """
        for regex in self._interesting_regex:
            if regex.search(url):
                return True
        return False

    def get_url_priority(self, url):
        """
        URL 우선순위 반환

        Args:
            url: 검사할 URL

        Returns:
            int: 우선순위 (0-10)
        """
        priority = 5

        if self.is_api_endpoint(url):
            priority += 3

        if self.is_interesting_url(url):
            priority += 2

        if '?' in url:
            priority += 1

        if len(url) > 500:
            priority -= 1

        return min(10, max(0, priority))

    @staticmethod
    def has_query_params(url):
        """
        URL에 쿼리 파라미터가 있는지 확인

        Args:
            url: 검사할 URL

        Returns:
            bool: 쿼리 파라미터 존재 여부
        """
        parsed = urlparse(url)
        return bool(parsed.query)

    @staticmethod
    def get_query_params(url):
        """
        URL에서 쿼리 파라미터 추출

        Args:
            url: 대상 URL

        Returns:
            dict: 쿼리 파라미터 딕셔너리
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            return {k: v[0] if len(v) == 1 else v for k, v in params.items()}
        except Exception:
            return {}

    @staticmethod
    def get_base_url(url):
        """
        URL에서 쿼리 스트링 제거한 기본 URL 반환

        Args:
            url: 대상 URL

        Returns:
            str: 기본 URL
        """
        try:
            parsed = urlparse(url)
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        except Exception:
            return url.split('?')[0]

    @staticmethod
    def get_path_segments(url):
        """
        URL 경로를 세그먼트로 분리

        Args:
            url: 대상 URL

        Returns:
            list: 경로 세그먼트 리스트
        """
        try:
            parsed = urlparse(url)
            path = parsed.path.strip('/')
            if not path:
                return []
            return path.split('/')
        except Exception:
            return []

    @staticmethod
    def extract_domain(url):
        """
        URL에서 도메인 추출

        Args:
            url: 대상 URL

        Returns:
            str: 도메인
        """
        try:
            return urlparse(url).netloc.lower()
        except Exception:
            return ""

    def is_same_domain(self, url1, url2):
        """
        두 URL이 같은 도메인인지 확인

        Args:
            url1: 첫 번째 URL
            url2: 두 번째 URL

        Returns:
            bool: 같은 도메인 여부
        """
        return self.extract_domain(url1) == self.extract_domain(url2)

    @staticmethod
    def is_same_origin(url1, url2):
        """
        두 URL이 같은 출처인지 확인

        Args:
            url1: 첫 번째 URL
            url2: 두 번째 URL

        Returns:
            bool: 같은 출처 여부
        """
        try:
            parsed1 = urlparse(url1)
            parsed2 = urlparse(url2)
            return (
                parsed1.scheme == parsed2.scheme and
                parsed1.netloc == parsed2.netloc
            )
        except Exception:
            return False

    def add_allowed_domain(self, domain):
        """허용 도메인 추가"""
        domain = domain.lower().strip()
        self.allowed_domains.add(domain)
        logger.info("허용 도메인 추가: %s", domain)

    def add_excluded_domain(self, domain):
        """제외 도메인 추가"""
        domain = domain.lower().strip()
        self.excluded_domains.add(domain)
        logger.info("제외 도메인 추가: %s", domain)

    def add_excluded_pattern(self, pattern):
        """제외 패턴 추가"""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            self._excluded_regex.append(compiled)
            logger.info("제외 패턴 추가: %s", pattern)
        except re.error as e:
            logger.error("잘못된 정규식 패턴 (%s): %s", pattern, e)

    def add_api_pattern(self, pattern):
        """API 패턴 추가"""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            self._api_regex.append(compiled)
            logger.info("API 패턴 추가: %s", pattern)
        except re.error as e:
            logger.error("잘못된 정규식 패턴 (%s): %s", pattern, e)