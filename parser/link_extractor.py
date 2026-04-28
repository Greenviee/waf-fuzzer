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
        
        # 상대 경로 내 콜론(:) 오인 방지 로직 (original_parsed 활용)
        original_parsed = urlparse(url)
        if original_parsed.scheme and original_parsed.scheme.lower() in IGNORED_SCHEMES:
            return None
        
        if parsed.scheme not in ('http', 'https'):
            return None
        
        return absolute
    except Exception as e:
        logger.debug("URL 정규화 실패: url=%s err=%s", url[:100], e)
        return None


def parse_params(url: str) -> Dict[str, List[str]]:
    try:
        return parse_qs(urlparse(url).query, keep_blank_values=True)
    except Exception as e:
        logger.debug("파라미터 파싱 실패: url=%s err=%s", url[:100], e)
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


def extract_form_links(soup: BeautifulSoup, base_url: str, seen: Set[str]) -> List[dict]:
    links = []
    for form in soup.find_all('form'):
        method = get_attr(form, 'method', 'GET').upper()
        if method not in ('GET', 'POST'): method = 'GET'
        
        action = get_attr(form, 'action') or base_url
        url = normalize_url(action, base_url)
        if not url: continue
        
        key = make_seen_key(url, method)
        if key in seen: continue
        seen.add(key)
        
        # _extract_form_params 기능 통합 연동
        params = _extract_form_params(form)
        links.append({
            'url': url, 'method': method, 'params': params, 'source': 'form'
        })
    return links


def _extract_form_params(form: Tag) -> Dict[str, List[str]]:
    params: Dict[str, List[str]] = {}
    for inp in form.find_all(['input', 'select', 'textarea']):
        name = get_attr(inp, 'name')
        if not name: continue
        
        inp_type = get_attr(inp, 'type', 'text').lower()
        if inp_type in ('submit', 'button', 'reset', 'image'): continue
        
        value = get_attr(inp, 'value')
        if inp.name == 'select':
            opt = inp.find('option', selected=True) or inp.find('option')
            if opt: value = get_attr(opt, 'value')
        
        params.setdefault(name, []).append(value)
    return params


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
    
    # 현대적인 data- 속성 대응
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
    content = content[:50000] # ReDoS 보호용 크기 제한
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
        
        # 정규식 캡처 그룹(match.group(1)) 활용
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
    include_forms: bool = True,
    include_js: bool = True,
    include_media: bool = True,
    include_meta: bool = True,
) -> List[dict]:
    """
    HTML 소스 또는 파싱된 객체로부터 공격 가능한 모든 경로 추출
    - AsyncHTMLParser 및 form_extractor와 타입 호환성 보장
    """
    if not html_or_soup or not base_url: return []
    
    # 지적사항 반영: 타입별 안전한 soup 객체 확보
    if isinstance(html_or_soup, str):
        try:
            soup = BeautifulSoup(html_or_soup, 'html.parser')
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
    
    # 링크 수집 단계
    links.extend(extract_anchor_links(soup, base_url, seen))
    if include_meta:
        links.extend(extract_link_tags(soup, base_url, seen))
        links.extend(extract_meta_refresh(soup, base_url, seen))
    if include_forms:
        links.extend(extract_form_links(soup, base_url, seen))
    if include_js:
        links.extend(extract_js_links(soup, base_url, seen))
    if include_media:
        links.extend(extract_media_links(soup, base_url, seen))
    
    # 외부 도메인 필터링 및 보안 분석
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
