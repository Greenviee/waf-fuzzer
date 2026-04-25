import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
import urllib3
from typing import Dict, List, Optional, Union

# SSL 경고 무시 (verify=False 사용 시 출력 방지)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HTMLParser:
    """웹 취약점 스캐너용 HTML 파서"""
    
    def __init__(self, timeout=10, verify_ssl=True):
        """
        HTMLParser 초기화
        
        Args:
            timeout (int): HTTP 요청 타임아웃
            verify_ssl (bool): SSL 인증서 검증 여부 (False로 설정하면 자체서명 인증서도 허용)
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Scanner-Bot-v1.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ko-KR,ko;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }

    def parse_from_url(self, url: str) -> Dict:
        """
        URL에서 HTML을 가져와 파싱
        
        Args:
            url (str): 대상 URL
            
        Returns:
            dict: 파싱 결과
        """
        try:
            logger.info(f"URL 파싱 시작: {url}")
            
            # URL 형식 검증 및 정규화
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # HTTP 요청
            response = requests.get(
                url, 
                headers=self.headers, 
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            # HTTP 상태 코드 검사
            response.raise_for_status()  # 4xx, 5xx 에러 시 예외 발생
            
            # 인코딩 자동 설정 (한글 깨짐 방지)
            if response.encoding is None or response.encoding == 'ISO-8859-1':
                response.encoding = response.apparent_encoding
            
            # HTML 파싱 (lxml이 없으면 html.parser로 fallback)
            try:
                soup = BeautifulSoup(response.text, 'lxml')
            except Exception:
                logger.warning("lxml 파서 사용 실패, html.parser로 fallback")
                soup = BeautifulSoup(response.text, 'html.parser')
            
            logger.info(f"파싱 성공: {response.url} (상태코드: {response.status_code})")
            
            return {
                'success': True,
                'soup': soup,
                'base_url': response.url,  # 리다이렉트된 최종 URL
                'status_code': response.status_code,
                'headers': dict(response.headers),  # 응답 헤더 정보
                'content_type': response.headers.get('content-type', ''),
                'error': None
            }
            
        except requests.exceptions.Timeout:
            error_msg = f"요청 타임아웃: {url}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg, 'base_url': url}
            
        except requests.exceptions.ConnectionError as e:
            error_msg = f"연결 실패: {url} - {str(e)}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg, 'base_url': url}
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP 오류: {url} - {str(e)}"
            logger.error(error_msg)
            return {
                'success': False, 
                'error': error_msg, 
                'base_url': url,
                'status_code': e.response.status_code if e.response else None
            }
            
        except Exception as e:
            error_msg = f"예상치 못한 오류: {url} - {str(e)}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg, 'base_url': url}

    def parse_html_string(self, html_string: str, base_url: Optional[str] = None) -> Dict:
        """
        HTML 문자열을 직접 파싱
        
        Args:
            html_string (str): HTML 문자열
            base_url (str, optional): 상대 URL 해석용 기준 URL
            
        Returns:
            dict: 파싱 결과
        """
        try:
            if not html_string or not html_string.strip():
                return {
                    'success': False,
                    'error': '빈 HTML 문자열',
                    'base_url': base_url
                }
            
            # HTML 파싱
            try:
                soup = BeautifulSoup(html_string, 'lxml')
            except Exception:
                soup = BeautifulSoup(html_string, 'html.parser')
            
            logger.info("HTML 문자열 파싱 완료")
            
            return {
                'success': True,
                'soup': soup,
                'base_url': base_url,
                'error': None
            }
            
        except Exception as e:
            error_msg = f"HTML 파싱 오류: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg,
                'base_url': base_url
            }

    def extract_links(self, soup: BeautifulSoup, base_url: str, 
                     same_domain_only: bool = True) -> List[str]:
        """
        취약점 스캔 대상 링크들을 수집
        
        Args:
            soup (BeautifulSoup): 파싱된 HTML 객체
            base_url (str): 기준 URL
            same_domain_only (bool): 같은 도메인만 수집할지 여부
            
        Returns:
            List[str]: 링크 목록
        """
        links = set()
        base_domain = urlparse(base_url).netloc
        
        # <a> 태그의 href 속성
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href'].strip()
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            
            full_url = urljoin(base_url, href)
            
            # 같은 도메인만 수집하는 옵션
            if same_domain_only:
                if urlparse(full_url).netloc == base_domain:
                    links.add(full_url)
            else:
                links.add(full_url)
        
        # <form> 태그의 action 속성도 포함
        for form_tag in soup.find_all('form', action=True):
            action = form_tag['action'].strip()
            if action:
                full_url = urljoin(base_url, action)
                if same_domain_only:
                    if urlparse(full_url).netloc == base_domain:
                        links.add(full_url)
                else:
                    links.add(full_url)
        
        logger.info(f"링크 추출 완료: {len(links)}개")
        return sorted(list(links))

    def extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """
        폼 정보 추출 (취약점 스캔용)
        
        Args:
            soup (BeautifulSoup): 파싱된 HTML 객체
            base_url (str): 기준 URL
            
        Returns:
            List[Dict]: 폼 정보 목록
        """
        forms = []
        
        for i, form_tag in enumerate(soup.find_all('form')):
            form_data = {
                'index': i,
                'action': urljoin(base_url, form_tag.get('action', '')),
                'method': form_tag.get('method', 'get').lower(),
                'inputs': [],
                'has_csrf_token': False
            }
            
            # 입력 필드들 수집
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required')
                }
                form_data['inputs'].append(input_data)
                
                # CSRF 토큰 검사
                if input_data['name'] and any(token in input_data['name'].lower() 
                                            for token in ['csrf', 'token', '_token']):
                    form_data['has_csrf_token'] = True
            
            forms.append(form_data)
        
        logger.info(f"폼 추출 완료: {len(forms)}개")
        return forms

# 편의 함수들
def parse_url(url: str, timeout: int = 10, verify_ssl: bool = True) -> Dict:
    """URL 파싱 편의 함수"""
    parser = HTMLParser(timeout=timeout, verify_ssl=verify_ssl)
    return parser.parse_from_url(url)

def parse_html(html_string: str, base_url: Optional[str] = None) -> Dict:
    """HTML 문자열 파싱 편의 함수"""
    parser = HTMLParser()
    return parser.parse_html_string(html_string, base_url)

# 테스트 코드
if __name__ == "__main__":
    print("=== 웹 취약점 스캐너용 HTML Parser 테스트 ===")
    
    # 1. URL 파싱 테스트
    print("\n1. URL 파싱 테스트:")
    result = parse_url("https://httpbin.org/forms/post", verify_ssl=True)
    
    if result['success']:
        print(f"✅ 파싱 성공!")
        print(f"   최종 URL: {result['base_url']}")
        print(f"   상태 코드: {result['status_code']}")
        print(f"   Content-Type: {result['content_type']}")
        
        # 링크 추출 테스트
        parser = HTMLParser()
        links = parser.extract_links(result['soup'], result['base_url'])
        print(f"   추출된 링크: {len(links)}개")
        
        # 폼 추출 테스트
        forms = parser.extract_forms(result['soup'], result['base_url'])
        print(f"   추출된 폼: {len(forms)}개")
        if forms:
            print(f"   첫 번째 폼: {forms[0]['method'].upper()} {forms[0]['action']}")
    else:
        print(f"❌ 파싱 실패: {result['error']}")
    
    # 2. SSL 비활성화 테스트
    print("\n2. SSL 검증 비활성화 테스트:")
    result = parse_url("https://self-signed.badssl.com", verify_ssl=False)
    print(f"SSL 비활성화 결과: {'성공' if result['success'] else '실패'}")