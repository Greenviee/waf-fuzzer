"""
Link Extractor Module for Web Vulnerability Scanner
BeautifulSoup 객체에서 링크와 query 파라미터를 추출하여 정형화된 데이터로 반환

개선사항:
- 서브도메인 허용 (보안 스캐너 특화)
- 중복 제거 버그 수정 (unhashable 오류 방지)
- REST API 탐지 확장
- 로그 안전성 확보 (raw_html repr 처리)
- JavaScript 분석 한계 명시

Note:
- JavaScript 분석은 heuristic만 지원 (template literal, 동적 생성 제외)
- 도메인 필터링은 단순 suffix 매칭 (Public Suffix List 미지원)
- 위험도 스코어는 파라미터명 기반 (값 내용 분석 제외)
"""

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Any, Tuple, Set, Pattern
from typing_extensions import TypedDict, NotRequired

# 로깅 설정 (basicConfig 제거 - 상위 모듈에서 설정)
logger = logging.getLogger(__name__)

# 설정 클래스
@dataclass
class LinkExtractorConfig:
    """링크 추출기 설정 (성능 최적화된 정규식 포함)"""
    
    # 제외할 링크 패턴
    excluded_schemes: Set[str] = field(default_factory=lambda: {
        'javascript:', 'mailto:', 'tel:', 'ftp:', 'file:'
    })
    
    # 제외할 앵커 패턴
    excluded_anchors: Set[str] = field(default_factory=lambda: {
        '#', 'javascript:void(0)', 'javascript:;'
    })
    
    # JavaScript URL 패턴 (heuristic extraction only, not full JS parsing)
    js_url_patterns: List[str] = field(default_factory=lambda: [
        r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
        r'(?:window\.)?open\s*\(\s*["\']([^"\']+)["\']',
        r'href\s*=\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.get\s*\(\s*["\']([^"\']+)["\']',
    ])
    
    # API 엔드포인트 패턴
    api_patterns: List[str] = field(default_factory=lambda: [
        r'["\']([^"\']*\/api\/[^"\']*)["\']',
        r'["\']([^"\']*\/ajax\/[^"\']*)["\']',
        r'["\']([^"\']*\.json[^"\']*)["\']',
        r'["\']([^"\']*\.xml[^"\']*)["\']',
    ])
    
    # 파라미터 기본값 설정
    default_param_values: Dict[str, str] = field(default_factory=lambda: {
        'id': '1', 'page': '1', 'limit': '10', 'q': 'test', 'search': 'test',
        'query': 'test', 'keyword': 'test', 'name': 'test', 'email': 'test@example.com',
        'user': 'testuser', 'category': '1', 'type': 'all', 'sort': 'desc', 'order': 'asc'
    })
    
    # 확장된 중요 파라미터 (보안 스캐너 특화)
    critical_params: Set[str] = field(default_factory=lambda: {
        # 기본 위험 파라미터
        'id', 'user', 'admin', 'file', 'path', 'dir', 'cmd', 'exec',
        # Open Redirect 후보
        'redirect', 'next', 'url', 'callback', 'return', 'dest',
        # LFI 후보
        'page', 'template', 'include', 'load', 'doc', 'download',
        # SSRF 후보
        'host', 'feed', 'proxy'
    })
    
    # raw_html 포함 여부 (메모리 효율성)
    include_raw_html: bool = False
    
    # 컴파일된 정규식 (성능 최적화)
    compiled_js_patterns: List[Pattern] = field(init=False)
    compiled_api_patterns: List[Pattern] = field(init=False)
    
    def __post_init__(self):
        """초기화 후 정규식 미리 컴파일 (성능 최적화)"""
        try:
            self.compiled_js_patterns = [
                re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                for pattern in self.js_url_patterns
            ]
            self.compiled_api_patterns = [
                re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                for pattern in self.api_patterns
            ]
            logger.debug("정규식 패턴 %d개 컴파일 완료", 
                        len(self.compiled_js_patterns) + len(self.compiled_api_patterns))
        except re.error as e:
            logger.error("정규식 컴파일 오류: %s", str(e))
            self.compiled_js_patterns = []
            self.compiled_api_patterns = []

# TypedDict 정의
class LinkInfo(TypedDict):
    """링크 정보 타입 정의"""
    # 필수 필드
    type: str
    url: str
    method: str
    parameters: Dict[str, Union[str, List[str]]]
    source: str
    
    # 선택적 필드
    link_text: NotRequired[str]
    raw_html: NotRequired[str]
    has_critical_params: NotRequired[bool]
    param_count: NotRequired[int]
    is_api_endpoint: NotRequired[bool]
    risk_score: NotRequired[int]

class LinkExtractor:
    """HTML에서 링크와 query 파라미터를 추출하는 클래스"""
    
    def __init__(self, 
                 soup: BeautifulSoup, 
                 base_url: Optional[str] = None,
                 config: Optional[LinkExtractorConfig] = None,
                 same_domain_only: bool = True):
        """
        LinkExtractor 초기화
        
        Args:
            soup (BeautifulSoup): 파싱된 HTML 객체
            base_url (str, optional): 기준 URL
            config (LinkExtractorConfig, optional): 설정 객체
            same_domain_only (bool): 같은 도메인만 추출할지 여부
        """
        self.soup = soup
        self.base_url = base_url
        self.config = config or LinkExtractorConfig()
        self.same_domain_only = same_domain_only
        self.base_domain = self._get_base_domain() if base_url else None

    def extract_links(self) -> List[LinkInfo]:
        """모든 링크와 query 파라미터를 추출"""
        try:
            links: List[LinkInfo] = []
            
            # 1. <a> 태그에서 링크 추출
            a_links = self._extract_a_tag_links()
            links.extend(a_links)
            
            # 2. <form> GET 메서드에서 링크 추출
            form_links = self._extract_form_get_links()
            links.extend(form_links)
            
            # 3. JavaScript에서 링크 추출 (heuristic only)
            js_links = self._extract_javascript_links()
            links.extend(js_links)
            
            # 4. 기타 태그에서 링크 추출
            other_links = self._extract_other_links()
            links.extend(other_links)
            
            # 5. 중복 제거 (버그 수정됨)
            unique_links = self._remove_duplicates_safe(links)
            
            logger.info("링크 추출 완료: %d개 (중복 제거 전: %d개)", len(unique_links), len(links))
            return unique_links
            
        except Exception as e:
            logger.error("링크 추출 중 오류 발생: %s", str(e))
            raise

    def _get_base_domain(self) -> Optional[str]:
        """기준 URL에서 도메인 추출"""
        if not self.base_url:
            return None
        
        try:
            parsed = urlparse(self.base_url)
            domain = parsed.netloc.lower()
            # www 제거 (서브도메인 허용을 위해)
            return domain.replace('www.', '') if domain.startswith('www.') else domain
        except Exception:
            return None

    def _is_same_domain(self, url: str) -> bool:
        """
        같은 도메인인지 확인 (서브도메인 허용 개선)
        
        개선사항: 서브도메인 허용하되 단순 suffix 매칭 사용
        한계: Public Suffix List 미지원 (tldextract 없이 단순화)
        """
        if not self.same_domain_only or not self.base_domain:
            return True
        
        try:
            parsed = urlparse(url)
            target_domain = parsed.netloc.lower()
            
            # www 제거
            if target_domain.startswith('www.'):
                target_domain = target_domain[4:]
            
            # 정확히 일치
            if target_domain == self.base_domain:
                return True
            
            # 서브도메인 허용 (단순 방식)
            # api.example.com, cdn.example.com 등 허용
            return target_domain.endswith('.' + self.base_domain)
            
        except Exception:
            return False

    def _extract_a_tag_links(self) -> List[LinkInfo]:
        """<a> 태그에서 링크 추출"""
        links = []
        
        for i, a_tag in enumerate(self.soup.find_all('a', href=True)):
            try:
                href = a_tag['href'].strip()
                
                if self._should_exclude_link(href):
                    continue
                
                full_url = self._convert_to_absolute_url(href)
                if not full_url or not self._is_same_domain(full_url):
                    continue
                
                base_url_part, parameters = self._parse_url_parameters(full_url)
                
                link_info: LinkInfo = {
                    'type': 'link',
                    'url': base_url_part,
                    'method': 'GET',
                    'parameters': parameters,
                    'source': 'a_tag',
                    'link_text': a_tag.get_text(strip=True)[:100] or '',
                    'has_critical_params': self._has_critical_params(parameters),
                    'param_count': len(parameters),
                    'is_api_endpoint': self._is_api_endpoint(base_url_part),
                    'risk_score': self._calculate_risk_score(parameters, base_url_part)
                }
                
                # 옵션에 따라 raw_html 포함 (안전한 처리)
                if self.config.include_raw_html:
                    link_info['raw_html'] = repr(str(a_tag)[:200])
                
                links.append(link_info)
                    
            except Exception as e:
                logger.warning("a 태그 처리 오류 (index: %d): %s", i, str(e))
                continue
        
        logger.info("<a> 태그 링크 추출: %d개", len(links))
        return links

    def _extract_form_get_links(self) -> List[LinkInfo]:
        """GET 메서드 폼에서 링크 추출"""
        links = []
        
        for i, form_tag in enumerate(self.soup.find_all('form')):
            try:
                method = form_tag.get('method', 'get').lower().strip()
                if method != 'get':
                    continue
                
                action = form_tag.get('action', '').strip() or self.base_url or ''
                full_url = self._convert_to_absolute_url(action)
                if not full_url or not self._is_same_domain(full_url):
                    continue
                
                base_url_part, url_params = self._parse_url_parameters(full_url)
                form_params = self._extract_form_parameters(form_tag)
                all_parameters = {**url_params, **form_params}
                
                link_info: LinkInfo = {
                    'type': 'link',
                    'url': base_url_part,
                    'method': 'GET',
                    'parameters': all_parameters,
                    'source': 'form_get',
                    'link_text': f"GET Form #{i}",
                    'has_critical_params': self._has_critical_params(all_parameters),
                    'param_count': len(all_parameters),
                    'is_api_endpoint': self._is_api_endpoint(base_url_part),
                    'risk_score': self._calculate_risk_score(all_parameters, base_url_part)
                }
                
                if self.config.include_raw_html:
                    link_info['raw_html'] = repr(str(form_tag)[:200])
                
                links.append(link_info)
                    
            except Exception as e:
                logger.warning("form 태그 처리 오류 (index: %d): %s", i, str(e))
                continue
        
        logger.info("GET 폼 링크 추출: %d개", len(links))
        return links

    def _extract_form_parameters(self, form_tag) -> Dict[str, str]:
        """폼의 입력 필드를 파라미터로 변환"""
        parameters = {}
        
        for element in form_tag.find_all(['input', 'select', 'textarea']):
            name = element.get('name', '').strip()
            if not name or element.get('type', '').lower() in {'submit', 'button', 'reset', 'image'}:
                continue
            
            default_value = self._get_parameter_default_value(name, element.get('type', 'text'), element)
            parameters[name] = default_value
        
        return parameters

    def _get_parameter_default_value(self, name: str, input_type: str, element) -> str:
        """파라미터의 기본값 결정"""
        name_lower = name.lower()
        for key, value in self.config.default_param_values.items():
            if key in name_lower:
                return value
        
        if input_type == 'email':
            return 'test@example.com'
        elif input_type == 'number':
            return '1'
        elif input_type == 'hidden':
            return element.get('value', '') or ''
        elif input_type in ['checkbox', 'radio']:
            return element.get('value', 'on') if element.has_attr('checked') else ''
        elif element.name == 'select':
            selected = element.find('option', selected=True)
            if selected:
                return selected.get('value', selected.get_text(strip=True)) or ''
            first = element.find('option')
            return first.get('value', first.get_text(strip=True)) if first else ''
        else:
            return element.get('value', 'test') or 'test'

    def _extract_javascript_links(self) -> List[LinkInfo]:
        """JavaScript에서 링크 추출 (heuristic extraction only, not full JS parsing)"""
        links = []
        
        # onclick 등 이벤트 핸들러
        for attr in ['onclick', 'onchange', 'onsubmit']:
            for element in self.soup.find_all(attrs={attr: True}):
                try:
                    js_code = element.get(attr, '')
                    urls = self._extract_urls_from_js_optimized(js_code)
                    
                    for url in urls:
                        full_url = self._convert_to_absolute_url(url)
                        if not full_url or not self._is_same_domain(full_url):
                            continue
                        
                        base_url_part, parameters = self._parse_url_parameters(full_url)
                        
                        link_info: LinkInfo = {
                            'type': 'link',
                            'url': base_url_part,
                            'method': 'GET',  # JS analysis limitation
                            'parameters': parameters,
                            'source': f'js_{attr}',
                            'link_text': element.get_text(strip=True)[:50] or '',
                            'has_critical_params': self._has_critical_params(parameters),
                            'param_count': len(parameters),
                            'is_api_endpoint': self._is_api_endpoint(base_url_part),
                            'risk_score': self._calculate_risk_score(parameters, base_url_part)
                        }
                        
                        if self.config.include_raw_html:
                            link_info['raw_html'] = repr(str(element)[:200])
                        
                        links.append(link_info)
                        
                except Exception as e:
                    logger.debug("이벤트 핸들러 처리 오류: %s", str(e))
                    continue
        
        # <script> 태그
        for script in self.soup.find_all('script'):
            try:
                script_content = script.get_text()
                if not script_content:
                    continue
                
                urls = self._extract_urls_from_js_optimized(script_content)
                
                for url in urls:
                    full_url = self._convert_to_absolute_url(url)
                    if not full_url or not self._is_same_domain(full_url):
                        continue
                    
                    base_url_part, parameters = self._parse_url_parameters(full_url)
                    
                    link_info: LinkInfo = {
                        'type': 'link',
                        'url': base_url_part,
                        'method': 'GET',
                        'parameters': parameters,
                        'source': 'js_script',
                        'link_text': 'JavaScript URL',
                        'has_critical_params': self._has_critical_params(parameters),
                        'param_count': len(parameters),
                        'is_api_endpoint': self._is_api_endpoint(base_url_part),
                        'risk_score': self._calculate_risk_score(parameters, base_url_part)
                    }
                    
                    if self.config.include_raw_html:
                        link_info['raw_html'] = repr(str(script)[:200])
                    
                    links.append(link_info)
                    
            except Exception as e:
                logger.debug("script 태그 처리 오류: %s", str(e))
                continue
        
        logger.info("JavaScript 링크 추출: %d개", len(links))
        return links

    def _extract_urls_from_js_optimized(self, js_code: str) -> List[str]:
        """JavaScript 코드에서 URL 추출 (미리 컴파일된 정규식 사용)"""
        urls = set()
        
        try:
            all_patterns = self.config.compiled_js_patterns + self.config.compiled_api_patterns
            
            for compiled_pattern in all_patterns:
                try:
                    matches = compiled_pattern.findall(js_code)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        
                        if self._looks_like_url_improved(match):
                            urls.add(match)
                            
                except Exception as e:
                    logger.debug("정규식 매칭 오류: %s", str(e))
                    continue
                    
        except Exception as e:
            logger.debug("JavaScript URL 추출 오류: %s", str(e))
        
        return list(urls)

    def _extract_other_links(self) -> List[LinkInfo]:
        """기타 태그에서 링크 추출 (iframe, img - 파라미터가 있는 경우만)"""
        links = []
        
        for tag_name, attr in [('iframe', 'src'), ('img', 'src')]:
            for element in self.soup.find_all(tag_name, **{attr: True}):
                try:
                    src = element[attr].strip()
                    if '?' not in src:  # 파라미터가 없으면 제외
                        continue
                    
                    full_url = self._convert_to_absolute_url(src)
                    if not full_url or not self._is_same_domain(full_url):
                        continue
                    
                    base_url_part, parameters = self._parse_url_parameters(full_url)
                    if not parameters:
                        continue
                    
                    link_info: LinkInfo = {
                        'type': 'link',
                        'url': base_url_part,
                        'method': 'GET',
                        'parameters': parameters,
                        'source': tag_name,
                        'link_text': element.get('alt', f'{tag_name} source') or f'{tag_name} source',
                        'has_critical_params': self._has_critical_params(parameters),
                        'param_count': len(parameters),
                        'is_api_endpoint': self._is_api_endpoint(base_url_part),
                        'risk_score': self._calculate_risk_score(parameters, base_url_part)
                    }
                    
                    if self.config.include_raw_html:
                        link_info['raw_html'] = repr(str(element)[:200])
                    
                    links.append(link_info)
                    
                except Exception as e:
                    logger.debug("%s 처리 오류: %s", tag_name, str(e))
                    continue
        
        logger.info("기타 링크 추출: %d개", len(links))
        return links

    def _should_exclude_link(self, href: str) -> bool:
        """링크를 제외할지 판단"""
        if not href or not href.strip():
            return True
        
        href_lower = href.lower().strip()
        
        for scheme in self.config.excluded_schemes:
            if href_lower.startswith(scheme):
                return True
        
        if href_lower in self.config.excluded_anchors:
            return True
        
        return False

    def _looks_like_url_improved(self, text: str) -> bool:
        """
        텍스트가 URL처럼 보이는지 확인 (REST API 고려 개선)
        
        개선사항: REST API 경로 탐지 확장
        """
        if not text or len(text) < 2:
            return False
        
        text = text.strip()
        
        # 명확한 URL 패턴
        if text.startswith(('/', './', '../', 'http:', 'https:')):
            return True
        
        # REST API 패턴 추가
        if any(api_pattern in text.lower() for api_pattern in ['/api/', '/v1/', '/admin/', '/graphql']):
            return True
        
        # 파라미터 있는 경우
        if '?' in text and ('=' in text or '&' in text):
            return True
        
        # 확장자 있는 경우
        if any(ext in text.lower() for ext in ['.html', '.php', '.jsp', '.asp', '.json', '.xml']):
            return True
        
        return False

    def _convert_to_absolute_url(self, url: str) -> Optional[str]:
        """URL을 절대 URL로 변환"""
        if not url:
            return None
        
        try:
            if url.startswith(('http://', 'https://')):
                return url
            
            if url.startswith('//'):
                return 'https:' + url
            
            if self.base_url:
                return urljoin(self.base_url, url)
            else:
                return url
                
        except Exception:
            return None

    def _parse_url_parameters(self, url: str) -> Tuple[str, Dict[str, Union[str, List[str]]]]:
        """URL에서 베이스 URL과 파라미터 분리"""
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            parameters = {}
            if parsed.query:
                query_params = parse_qs(parsed.query, keep_blank_values=True)
                for key, values in query_params.items():
                    parameters[key] = values[0] if len(values) == 1 else values
            
            return base_url, parameters
            
        except Exception:
            return url, {}

    def _has_critical_params(self, parameters: Dict[str, Any]) -> bool:
        """중요한 파라미터가 있는지 확인"""
        param_names = set(param.lower() for param in parameters.keys())
        return bool(param_names & self.config.critical_params)

    def _calculate_risk_score(self, parameters: Dict[str, Any], url: str) -> int:
        """URL 위험도 스코어 계산 (보안 스캐너 특화)"""
        score = 0
        param_names = set(param.lower() for param in parameters.keys())
        
        # Open Redirect 위험도
        open_redirect_params = {'redirect', 'next', 'url', 'callback', 'return', 'dest'}
        score += len(param_names & open_redirect_params) * 3
        
        # LFI 위험도
        lfi_params = {'file', 'page', 'template', 'include', 'load', 'doc'}
        score += len(param_names & lfi_params) * 4
        
        # SSRF 위험도
        ssrf_params = {'url', 'host', 'feed', 'proxy'}
        score += len(param_names & ssrf_params) * 3
        
        # 관리자 관련
        admin_params = {'admin', 'user', 'id'}
        score += len(param_names & admin_params) * 2
        
        # API 엔드포인트 보너스
        if self._is_api_endpoint(url):
            score += 2
        
        return min(score, 10)  # 최대 10점

    def _is_api_endpoint(self, url: str) -> bool:
        """API 엔드포인트인지 확인"""
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in ['/api/', '/ajax/', '.json', '.xml', '/rest/'])

    def _freeze_value(self, value: Any) -> Any:
        """
        값을 해시 가능한 형태로 변환 (중복 제거용)
        
        개선사항: unhashable type 오류 방지
        """
        if isinstance(value, list):
            return tuple(self._freeze_value(item) for item in value)
        elif isinstance(value, dict):
            return tuple(sorted((k, self._freeze_value(v)) for k, v in value.items()))
        elif isinstance(value, set):
            return tuple(sorted(self._freeze_value(item) for item in value))
        else:
            return value

    def _remove_duplicates_safe(self, links: List[LinkInfo]) -> List[LinkInfo]:
        """
        중복 링크 제거 (안전한 버전)
        
        개선사항: unhashable type 오류 완전 방지
        """
        seen = set()
        unique_links = []
        
        for link in links:
            try:
                # 안전한 파라미터 해싱
                frozen_params = self._freeze_value(link['parameters'])
                key = (link['url'], link['method'], frozen_params)
                
                if key not in seen:
                    seen.add(key)
                    unique_links.append(link)
                else:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("중복 링크 제거: %s", link['url'])
                        
            except Exception as e:
                logger.debug("중복 제거 처리 오류: %s", str(e))
                unique_links.append(link)  # 오류가 있어도 포함
        
        return unique_links

# 편의 함수들
def extract_links(soup: BeautifulSoup, 
                 base_url: Optional[str] = None,
                 config: Optional[LinkExtractorConfig] = None,
                 same_domain_only: bool = True) -> List[LinkInfo]:
    """BeautifulSoup 객체에서 링크 정보를 추출하는 편의 함수"""
    extractor = LinkExtractor(soup, base_url, config, same_domain_only)
    return extractor.extract_links()

def extract_links_from_html(html_string: str, 
                           base_url: Optional[str] = None,
                           config: Optional[LinkExtractorConfig] = None,
                           same_domain_only: bool = True) -> List[LinkInfo]:
    """HTML 문자열에서 직접 링크 추출"""
    soup = BeautifulSoup(html_string, 'html.parser')
    return extract_links(soup, base_url, config, same_domain_only)

def get_links_summary(links: List[LinkInfo]) -> Dict[str, Any]:
    """링크 추출 결과 요약 정보"""
    if not links:
        return {
            'total_links': 0, 'links_with_params': 0, 'critical_param_links': 0,
            'api_endpoints': 0, 'high_risk_links': 0, 'sources': {}, 'unique_domains': []
        }
    
    sources = {}
    for link in links:
        source = link.get('source', 'unknown')
        sources[source] = sources.get(source, 0) + 1
    
    domains = set()
    for link in links:
        try:
            domain = urlparse(link['url']).netloc
            if domain: 
                domains.add(domain)
        except: 
            pass
    
    summary = {
        'total_links': len(links),
        'links_with_params': len([l for l in links if l.get('param_count', 0) > 0]),
        'critical_param_links': len([l for l in links if l.get('has_critical_params', False)]),
        'api_endpoints': len([l for l in links if l.get('is_api_endpoint', False)]),
        'high_risk_links': len([l for l in links if l.get('risk_score', 0) >= 5]),
        'sources': sources,
        'unique_domains': list(domains)
    }
    
    logger.info("링크 요약 생성 완료: %d개 링크", summary['total_links'])
    return summary

# 테스트용 설정 팩토리
def create_test_extractor(soup: BeautifulSoup, base_url: Optional[str] = None) -> LinkExtractor:
    """테스트용 LinkExtractor 생성"""
    test_config = LinkExtractorConfig()
    test_config.include_raw_html = True
    return LinkExtractor(soup, base_url, test_config)

# 테스트 코드
if __name__ == "__main__":
    from bs4 import BeautifulSoup
    
    print("=== Link Extractor 최종 테스트 ===")
    
    # 테스트용 HTML
    test_html = """
    <html>
        <head>
            <script>
                function goToPage() {
                    window.location.href = '/api/data?id=123&type=json';
                }
            </script>
        </head>
        <body>
            <!-- 일반 링크들 -->
            <a href="/page1?tab=main">페이지 1</a>
            <a href="/search?q=test&category=news&limit=10">검색 결과</a>
            <a href="/admin/users?id=1">관리자 페이지</a>
            
            <!-- GET 폼 -->
            <form method="get" action="/search">
                <input type="text" name="keyword">
                <select name="sort">
                    <option value="date">날짜순</option>
                    <option value="relevance" selected>관련도순</option>
                </select>
                <input type="submit" value="검색">
            </form>
            
            <!-- JavaScript 링크 -->
            <button onclick="location.href='/profile?user=123'">프로필</button>
            <div onclick="window.open('/api/logout?redirect=/')">로그아웃</div>
            
            <!-- 파라미터 있는 미디어 -->
            <iframe src="/embed?video=abc123&autoplay=1"></iframe>
            <img src="/image.jpg?size=large&quality=high" alt="이미지">
            
            <!-- 위험한 파라미터들 -->
            <a href="/file?path=../../etc/passwd">파일</a>
            <a href="/redirect?url=http://evil.com">리다이렉트</a>
        </body>
    </html>
    """
    
    try:
        # 테스트 실행
        soup = BeautifulSoup(test_html, 'html.parser')
        base_url = "https://example.com"
        
        # 설정 생성 (raw_html 포함)
        config = LinkExtractorConfig()
        config.include_raw_html = True
        
        extractor = LinkExtractor(soup, base_url, config)
        links = extractor.extract_links()
        
        print(f"\n추출된 링크 개수: {len(links)}")
        print("-" * 80)
        
        for i, link in enumerate(links):
            print(f"\n링크 #{i+1}:")
            print(f"  URL: {link['url']}")
            print(f"  Method: {link['method']}")
            print(f"  Source: {link['source']}")
            print(f"  Parameters: {link['parameters']}")
            print(f"  Critical Params: {link.get('has_critical_params', False)}")
            print(f"  API Endpoint: {link.get('is_api_endpoint', False)}")
            print(f"  Risk Score: {link.get('risk_score', 0)}/10")
            if 'link_text' in link:
                print(f"  Text: {link['link_text']}")
        
        # 요약 정보
        print("\n" + "="*80)
        summary = get_links_summary(links)
        print("링크 추출 요약:")
        for key, value in summary.items():
            print(f"  {key}: {value}")
            
    except Exception as e:
        print(f"❌ 테스트 중 오류 발생: {e}")
        import traceback
        traceback.print_exc()