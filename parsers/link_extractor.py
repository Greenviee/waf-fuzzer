import re
import logging
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Optional, Set, Union
from bs4 import BeautifulSoup, Tag

logger = logging.getLogger(__name__)

# ============================================================================
# 상수 (공통 관리)
# ============================================================================

IGNORED_SCHEMES = frozenset(['javascript', 'mailto', 'tel', 'data', 'blob', 'file'])

CRITICAL_PARAMS = frozenset([
    'id', 'user', 'uid', 'file', 'path', 'dir', 'url', 'redirect', 'next',
    'cmd', 'exec', 'query', 'sql', 'token', 'key', 'admin', 'debug',
    'page', 'template', 'include', 'callback', 'download', 'load'
])

API_INDICATORS = frozenset(['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/ajax/', '/graphql'])

TARGET_RELS = frozenset(['canonical', 'next', 'prev', 'alternate'])

JS_URL_PATTERNS = [
    re.compile(r'''location\.href\s*=\s*["']([^"']{1,500})["']''', re.I),
    re.compile(r'''window\.open\s*\(\s*["']([^"']{1,500})["']''', re.I),
    re.compile(r'''\.href\s*=\s*["']([^"']{1,500})["']''', re.I),
]

META_REFRESH_PATTERN = re.compile(r'url\s*=\s*["\']?([^"\';\s>]{1,500})', re.I)


# ============================================================================
# 유틸리티
# ============================================================================

def get_attr(tag: Tag, attr: str, default: str = '') -> str:
    if not isinstance(tag, Tag):
        return default
    value = tag.get(attr)
    if value is None:
        return default
    if isinstance(value, list):
        return value[0] if value else default
    return str(value).strip()


def get_rel(tag: Tag) -> Set[str]:
    if not isinstance(tag, Tag):
        return set()
    value = tag.get('rel')
    if not value:
        return set()
    if isinstance(value, list):
        return {v.lower() for v in value}
    return {str(value).lower()}


def normalize_url(url: str, base_url: str) -> Optional[str]:
    if not url or not isinstance(url, str):
        return None

    url = url.strip()
    if not url or url == '#' or url.lower().startswith('javascript:'):
        return None

    try:
        absolute = urljoin(base_url, url)
        parsed = urlparse(absolute)

        original_parsed = urlparse(url)
        if original_parsed.scheme and original_parsed.scheme.lower() in IGNORED_SCHEMES:
            return None

        if parsed.scheme not in ('http', 'https'):
            return None

        return absolute
    except Exception as e:
        logger.debug("URL 정규화 실패: url=%s err=%s", url[:100], e)
        return None


def parse_params(url: str) -> Dict[str, str]: # ✨ [수정] 반환 타입을 Dict[str, str]로 고정
    try:
        # parse_qs의 결과: {'id': ['admin']}
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        # ✨ [정규화] 리스트의 첫 번째 값만 취하여 문자열로 변환
        return {k: v[0] if v else "" for k, v in qs.items()}
    except Exception as e:
        logger.debug("파라미터 파싱 실패: %s", e)
        return {}


def is_same_domain(url: str, base_domain: str) -> bool:
    try:
        domain = urlparse(url).netloc.lower()
        base = base_domain.lower()
        return domain == base or domain.endswith('.' + base)
    except Exception as e:
        logger.debug("도메인 검사 실패: url=%s err=%s", url[:100], e)
        return False


def make_seen_key(url: str, method: str = 'GET') -> str:
    return f"{method.upper()}:{url.lower().rstrip('/')}"


# ============================================================================
# 추출 세부 로직
# ============================================================================

def extract_anchor_links(soup: BeautifulSoup, base_url: str, seen: Set[str]) -> List[dict]:
    links = []
    for tag in soup.find_all('a'):
        href = get_attr(tag, 'href')
        url = normalize_url(href, base_url)
        if not url: continue

        key = make_seen_key(url, 'GET')
        if key in seen: continue
        seen.add(key)

        text = ''
        try:
            text = tag.get_text(strip=True)[:100]
        except Exception:
            pass

        links.append({
            'url': url, 'method': 'GET', 'params': parse_params(url),
            'source': 'anchor', 'text': text
        })
    return links


def extract_link_tags(soup: BeautifulSoup, base_url: str, seen: Set[str]) -> List[dict]:
    links = []
    for tag in soup.find_all('link'):
        href = get_attr(tag, 'href')
        url = normalize_url(href, base_url)
        if not url: continue

        rel_set = get_rel(tag)
        if not rel_set & TARGET_RELS: continue

        key = make_seen_key(url, 'GET')
        if key in seen: continue
        seen.add(key)

        links.append({
            'url': url, 'method': 'GET', 'params': parse_params(url),
            'source': 'link_tag', 'rel': list(rel_set)
        })
    return links


def extract_js_links(soup: BeautifulSoup, base_url: str, seen: Set[str]) -> List[dict]:
    links = []
    for script in soup.find_all('script'):
        if get_attr(script, 'src'): continue
        content = script.string or ''
        if content:
            links.extend(_extract_urls_from_js(content, base_url, seen, 'script'))

    for attr in ('onclick', 'onmouseover', 'onload'):
        for tag in soup.find_all(attrs={attr: True}):
            handler = get_attr(tag, attr)
            if handler:
                links.extend(_extract_urls_from_js(handler, base_url, seen, f'event_{attr}'))

    for attr in ('data-url', 'data-href', 'data-src', 'data-link'):
        for tag in soup.find_all(attrs={attr: True}):
            val = get_attr(tag, attr)
            url = normalize_url(val, base_url)
            if not url: continue

            key = make_seen_key(url, 'GET')
            if key in seen: continue
            seen.add(key)

            links.append({
                'url': url, 'method': 'GET', 'params': parse_params(url), 'source': attr
            })
    return links


def _extract_urls_from_js(content: str, base_url: str, seen: Set[str], source: str) -> List[dict]:
    links = []
    content = content[:50000]
    for pattern in JS_URL_PATTERNS:
        try:
            for match in pattern.findall(content):
                url = normalize_url(match, base_url)
                if not url: continue

                key = make_seen_key(url, 'GET')
                if key in seen: continue
                seen.add(key)

                links.append({
                    'url': url, 'method': 'GET', 'params': parse_params(url), 'source': source
                })
        except re.error as e:
            logger.debug("정규식 오류: %s", e)
    return links


def extract_meta_refresh(soup: BeautifulSoup, base_url: str, seen: Set[str]) -> List[dict]:
    links = []
    for meta in soup.find_all('meta', attrs={'http-equiv': True}):
        if get_attr(meta, 'http-equiv').lower() != 'refresh': continue

        content = get_attr(meta, 'content')
        if not content: continue

        match = META_REFRESH_PATTERN.search(content)
        if not match: continue

        url = normalize_url(match.group(1), base_url)
        if not url: continue

        key = make_seen_key(url, 'GET')
        if key in seen: continue
        seen.add(key)

        links.append({
            'url': url, 'method': 'GET', 'params': parse_params(url), 'source': 'meta_refresh'
        })
    return links


def extract_media_links(soup: BeautifulSoup, base_url: str, seen: Set[str]) -> List[dict]:
    links = []
    media_tags = [('iframe', 'src'), ('img', 'src'), ('video', 'src'), ('embed', 'src')]
    for tag_name, attr_name in media_tags:
        for tag in soup.find_all(tag_name):
            src = get_attr(tag, attr_name)
            url = normalize_url(src, base_url)
            if not url: continue

            params = parse_params(url)
            if not params: continue

            key = make_seen_key(url, 'GET')
            if key in seen: continue
            seen.add(key)

            links.append({
                'url': url, 'method': 'GET', 'params': params, 'source': f'media_{tag_name}'
            })
    return links


# ============================================================================
# 분석 및 인터페이스
# ============================================================================

def analyze_link(link: dict) -> None:
    """공격 지점(Attack Surface) 우선순위 분석"""
    params = link.get('params', {})
    param_names = {k.lower() for k in params.keys()}

    critical = list(param_names & CRITICAL_PARAMS)
    link['critical_params'] = critical

    url_path = urlparse(link.get('url', '')).path.lower()
    link['is_api'] = any(indicator in url_path for indicator in API_INDICATORS)

    score = len(critical) * 2
    if link['is_api']: score += 2
    if link.get('method') == 'POST': score += 1
    if len(params) > 5: score += 1
    link['risk_score'] = min(score, 10)


def extract_links(
        html_or_soup: Union[str, BeautifulSoup],
        base_url: str,
        include_external: bool = False,
        include_js: bool = True,
        include_media: bool = True,
        include_meta: bool = True,
) -> List[dict]:
    """
    HTML 소스 또는 파싱된 객체로부터 링크 추출
    (폼 추출은 form_extractor 모듈에서 전담)
    """
    if not html_or_soup or not base_url: return []

    if isinstance(html_or_soup, str):
        try:
            soup = BeautifulSoup(html_or_soup, 'html.parsers')
        except Exception as e:
            logger.error("HTML 파싱 실패: %s", e)
            return []
    elif isinstance(html_or_soup, BeautifulSoup):
        soup = html_or_soup
    else:
        logger.error("지원하지 않는 타입: %s", type(html_or_soup).__name__)
        return []

    base_domain = urlparse(base_url).netloc.lower()
    seen: Set[str] = set()
    links: List[dict] = []

    links.extend(extract_anchor_links(soup, base_url, seen))

    if include_meta:
        links.extend(extract_link_tags(soup, base_url, seen))
        links.extend(extract_meta_refresh(soup, base_url, seen))

    if include_js:
        links.extend(extract_js_links(soup, base_url, seen))

    if include_media:
        links.extend(extract_media_links(soup, base_url, seen))

    if not include_external:
        links = [l for l in links if is_same_domain(l['url'], base_domain)]

    for link in links:
        analyze_link(link)

    return links


def get_summary(links: List[dict]) -> dict:
    if not links: return {'total': 0}
    methods, sources = {}, {}
    for link in links:
        m = link.get('method', 'GET')
        methods[m] = methods.get(m, 0) + 1
        s = link.get('source', 'unknown')
        sources[s] = sources.get(s, 0) + 1

    return {
        'total': len(links), 'methods': methods, 'sources': sources,
        'with_params': sum(1 for l in links if l.get('params')),
        'with_critical': sum(1 for l in links if l.get('critical_params')),
        'high_risk': sum(1 for l in links if l.get('risk_score', 0) >= 7),
    }