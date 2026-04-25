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
    EXCLUDED_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp',
        '.css', '.js', '.map',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.tar', '.gz', '.7z',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
        '.exe', '.dll', '.so', '.dmg', '.apk'
    }

    DEFAULT_EXCLUDED_PATTERNS = [
        r'/logout', r'/signout', r'/sign-out', r'/log-out', r'/delete',
        r'/remove', r'/unsubscribe', r'/deactivate', r'\?.*logout',
        r'\?.*delete', r'\?.*remove',
    ]

    API_PATTERNS = [
        r'/api/', r'/v\d+/', r'/graphql', r'/rest/', r'/ajax/', r'/json/',
        r'/xml/', r'\.json$', r'\.xml$',
    ]

    INTERESTING_PATTERNS = [
        r'/admin', r'/login', r'/register', r'/signup', r'/upload',
        r'/download', r'/search', r'/user', r'/profile', r'/account',
        r'/settings', r'/config', r'/edit', r'/update', r'/create',
        r'/add', r'/submit', r'/process', r'/callback', r'/webhook', r'/redirect',
    ]

    def __init__(
            self,
            allowed_domains=None,
            excluded_patterns=None,
            max_url_length=2048,
            max_same_structure=3
    ):
        if allowed_domains is None:
            self.allowed_domains = set()
        else:
            self.allowed_domains = set(allowed_domains)

        self.excluded_domains = set()
        self.max_url_length = max_url_length
        self.allowed_schemes = {'http', 'https'}

        self.url_structure_counts = {}
        self.max_same_structure = max_same_structure

        patterns = self.DEFAULT_EXCLUDED_PATTERNS.copy()
        if excluded_patterns is not None:
            patterns.extend(excluded_patterns)

        self._excluded_regex = [re.compile(p, re.IGNORECASE) for p in patterns]
        self._api_regex = [re.compile(p, re.IGNORECASE) for p in self.API_PATTERNS]
        self._interesting_regex = [re.compile(p, re.IGNORECASE) for p in self.INTERESTING_PATTERNS]

        logger.debug("URL 필터 초기화: 허용 도메인=%s", self.allowed_domains)

    def should_crawl(self, url: str) -> bool:
        """URL을 크롤링해야 하는지 결정"""
        try:
            parsed = urlparse(url)

            if parsed.scheme not in self.allowed_schemes:
                return False

            if len(url) > self.max_url_length:
                return False

            if not self._is_domain_allowed(parsed.netloc):
                return False

            if self._has_excluded_extension(parsed.path):
                return False

            if self._matches_excluded_pattern(url):
                return False

            if parsed.query:
                query_keys = tuple(sorted(parse_qs(parsed.query).keys()))
                structure_hash = hash((parsed.path, query_keys))

                if self.url_structure_counts.get(structure_hash, 0) >= self.max_same_structure:
                    logger.debug("동일 URL 구조 제한 초과 방지: %s", url)
                    return False

                self.url_structure_counts[structure_hash] = self.url_structure_counts.get(structure_hash, 0) + 1

            return True

        except Exception as e:
            logger.warning("URL 필터링 오류 (%s): %s", url, e)
            return False

    def _is_domain_allowed(self, domain: str) -> bool:
        if domain in self.excluded_domains:
            return False
        if self.allowed_domains:
            for allowed in self.allowed_domains:
                if domain == allowed or domain.endswith('.' + allowed):
                    return True
            return False
        return True

    def _has_excluded_extension(self, path: str) -> bool:
        path_lower = path.lower()
        for ext in self.EXCLUDED_EXTENSIONS:
            if path_lower.endswith(ext):
                return True
        return False

    def _matches_excluded_pattern(self, url: str) -> bool:
        for regex in self._excluded_regex:
            if regex.search(url):
                return True
        return False

    @staticmethod
    def normalize_url(url: str) -> str:
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            if ':80' in netloc and scheme == 'http':
                netloc = netloc.replace(':80', '')
            elif ':443' in netloc and scheme == 'https':
                netloc = netloc.replace(':443', '')

            path = parsed.path or '/'
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

            return urlunparse((scheme, netloc, path, '', query, ''))
        # noinspection PyBroadException
        except Exception as e:
            logger.debug("URL 정규화 실패 (%s): %s", url, e)
            return str(url)

    def is_api_endpoint(self, url: str) -> bool:
        for regex in self._api_regex:
            if regex.search(url):
                return True
        return False

    def is_interesting_url(self, url: str) -> bool:
        for regex in self._interesting_regex:
            if regex.search(url):
                return True
        return False

    def get_url_priority(self, url: str) -> int:
        priority = 5
        if self.is_api_endpoint(url): priority += 3
        if self.is_interesting_url(url): priority += 2
        if '?' in url: priority += 1
        if len(url) > 500: priority -= 1
        return min(10, max(0, priority))

    @staticmethod
    def has_query_params(url: str) -> bool:
        return bool(urlparse(url).query)

    @staticmethod
    def get_query_params(url: str) -> dict:
        try:
            params = parse_qs(urlparse(url).query, keep_blank_values=True)
            return {str(k): str(v[0]) if len(v) == 1 else v for k, v in params.items()}
        # noinspection PyBroadException
        except Exception as e:
            logger.debug("쿼리 파라미터 추출 실패 (%s): %s", url, e)
            return {}

    @staticmethod
    def get_base_url(url: str) -> str:
        try:
            parsed = urlparse(url)
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        # noinspection PyBroadException
        except Exception as e:
            logger.debug("기본 URL 추출 실패 (%s): %s", url, e)
            return str(url).split('?')[0]

    @staticmethod
    def get_path_segments(url: str) -> list:
        try:
            path = urlparse(url).path.strip('/')
            return path.split('/') if path else []
        # noinspection PyBroadException
        except Exception as e:
            logger.debug("경로 세그먼트 추출 실패 (%s): %s", url, e)
            return []

    @staticmethod
    def extract_domain(url: str) -> str:
        try:
            return urlparse(url).netloc.lower()
        # noinspection PyBroadException
        except Exception as e:
            logger.debug("도메인 추출 실패 (%s): %s", url, e)
            return ""

    def is_same_domain(self, url1: str, url2: str) -> bool:
        return self.extract_domain(url1) == self.extract_domain(url2)

    @staticmethod
    def is_same_origin(url1: str, url2: str) -> bool:
        try:
            parsed1 = urlparse(url1)
            parsed2 = urlparse(url2)
            return parsed1.scheme == parsed2.scheme and parsed1.netloc == parsed2.netloc
        # noinspection PyBroadException
        except Exception as e:
            logger.debug("동일 출처 확인 실패: %s", e)
            return False

    def add_allowed_domain(self, domain: str):
        self.allowed_domains.add(domain.lower().strip())

    def add_excluded_domain(self, domain: str):
        self.excluded_domains.add(domain.lower().strip())

    def add_excluded_pattern(self, pattern: str):
        try:
            self._excluded_regex.append(re.compile(str(pattern), re.IGNORECASE))
        except re.error as e:
            logger.debug("잘못된 정규식 패턴 추가 시도 (%s): %s", pattern, e)

    def add_api_pattern(self, pattern: str):
        try:
            self._api_regex.append(re.compile(str(pattern), re.IGNORECASE))
        except re.error as e:
            logger.debug("잘못된 API 정규식 패턴 추가 시도 (%s): %s", pattern, e)