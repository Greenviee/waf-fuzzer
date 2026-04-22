"""
URL 필터
크롤링 대상 URL을 필터링하고 정규화

담당: 팀 A - 인원 1 (크롤러 엔진 & 네트워크 담당)
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

        logger.debug("URL 필터 초기화: 허용 도메인=%s", self.allowed_domains)

    def should_crawl(self, url):
        """
        URL을 크롤링해야 하는지 결정

        Args:
            url: 검사할 URL

        Returns:
            크롤링 여부 (True/False)
        """
        try:
            parsed = urlparse(url)

            # 1. 스킴 체크 (http, https만 허용)
            if parsed.scheme not in self.allowed_schemes:
                logger.debug("스킴 불허: %s", url)
                return False

            # 2. URL 길이 체크
            if len(url) > self.max_url_length:
                logger.debug("URL 너무 김: %s...", url[:50])
                return False

            # 3. 도메인 체크
            if not self._is_domain_allowed(parsed.netloc):
                logger.debug("도메인 불허: %s", parsed.netloc)
                return False

            # 4. 확장자 체크
            if self._has_excluded_extension(parsed.path):
                logger.debug("확장자 제외: %s", url)
                return False

            # 5. 제외 패턴 체크
            if self._matches_excluded_pattern(url):
                logger.debug("패턴 제외: %s", url)
                return False

            return True

        except Exception as e:
            logger.warning("URL 필터링 오류 (%s): %s", url, e)
            return False

    def _is_domain_allowed(self, domain):
        """도메인 허용 여부 확인"""
        # 제외 도메인 체크
        if domain in self.excluded_domains:
            return False

        # 허용 도메인이 설정된 경우에만 체크
        if self.allowed_domains:
            # 정확히 일치하거나 서브도메인인 경우 허용
            for allowed in self.allowed_domains:
                if domain == allowed:
                    return True
                if domain.endswith('.' + allowed):
                    return True
            return False

        # 허용 도메인이 설정되지 않으면 모두 허용
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

    def normalize_url(self, url):
        """
        URL 정규화 (중복 방지용)

        정규화 규칙:
        - 스킴/호스트 소문자 변환
        - 기본 포트 제거 (80, 443)
        - 쿼리 파라미터 정렬
        - 프래그먼트(#) 제거
        - 중복 슬래시 제거

        Args:
            url: 원본 URL

        Returns:
            정규화된 URL
        """
        try:
            parsed = urlparse(url)

            # 스킴 소문자
            scheme = parsed.scheme.lower()

            # 호스트 소문자 + 기본 포트 제거
            netloc = parsed.netloc.lower()
            if ':80' in netloc and scheme == 'http':
                netloc = netloc.replace(':80', '')
            elif ':443' in netloc and scheme == 'https':
                netloc = netloc.replace(':443', '')

            # 경로 정규화
            path = parsed.path
            if not path:
                path = '/'
            path = re.sub(r'/+', '/', path)  # 중복 슬래시 제거
            path = unquote(path)  # URL 디코딩

            # 쿼리 파라미터 정렬
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

            # 프래그먼트 제거하고 재조합
            normalized = urlunparse((scheme, netloc, path, '', query, ''))

            return normalized

        except Exception as e:
            logger.warning("URL 정규화 실패 (%s): %s", url, e)
            return url

    def add_allowed_domain(self, domain):
        """
        허용 도메인 추가

        Args:
            domain: 추가할 도메인
        """
        domain = domain.lower().strip()
        self.allowed_domains.add(domain)
        logger.info("허용 도메인 추가: %s", domain)

    def add_excluded_domain(self, domain):
        """
        제외 도메인 추가

        Args:
            domain: 제외할 도메인
        """
        domain = domain.lower().strip()
        self.excluded_domains.add(domain)
        logger.info("제외 도메인 추가: %s", domain)

    def add_excluded_pattern(self, pattern):
        """
        제외 패턴 추가

        Args:
            pattern: 제외할 정규식 패턴
        """
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            self._excluded_regex.append(compiled)
            logger.info("제외 패턴 추가: %s", pattern)
        except re.error as e:
            logger.error("잘못된 정규식 패턴 (%s): %s", pattern, e)

    def extract_domain(self, url):
        """URL에서 도메인 추출"""
        try:
            return urlparse(url).netloc.lower()
        except Exception:
            return ""

    def is_same_domain(self, url1, url2):
        """두 URL이 같은 도메인인지 확인"""
        return self.extract_domain(url1) == self.extract_domain(url2)