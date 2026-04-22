"""
Form Extractor Module for Web Vulnerability Scanner
BeautifulSoup 객체에서 폼 정보를 추출하여 딕셔너리 리스트로 반환
surface_builder.py에서 AttackSurface 객체로 변환할 데이터를 제공
"""

from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging
from collections import defaultdict

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_forms(soup, base_url=None):
    """
    BeautifulSoup 객체에서 폼 정보를 추출
    
    Args:
        soup (BeautifulSoup): 파싱된 HTML 객체
        base_url (str, optional): 상대 URL 해석용 기준 URL
        
    Returns:
        List[Dict]: 폼 정보 딕셔너리 리스트
            [
                {
                    'type': 'form',
                    'action': str,           # 폼 액션 URL (절대 URL)
                    'method': str,           # HTTP 메서드 (get/post/put/delete)
                    'enctype': str,          # 인코딩 타입
                    'parameters': Dict,      # {파라미터명: 기본값}
                    'has_csrf_token': bool,  # CSRF 토큰 유무
                    'csrf_token': Dict,      # CSRF 토큰 정보
                    'form_info': Dict,       # 추가 메타데이터
                    'raw_html': str          # 원본 HTML
                }
            ]
    """
    try:
        forms = []
        form_tags = soup.find_all('form')
        
        if not form_tags:
            logger.info("추출할 폼이 없습니다.")
            return forms
            
        logger.info(f"{len(form_tags)}개의 폼을 발견했습니다.")
        
        for i, form_tag in enumerate(form_tags):
            form_data = _extract_single_form(form_tag, i, base_url)
            forms.append(form_data)
        
        logger.info(f"폼 추출 완료: {len(forms)}개")
        return forms
        
    except Exception as e:
        logger.error(f"폼 추출 중 오류 발생: {str(e)}")
        raise  # 원본 예외 그대로 재발생

def _extract_single_form(form_tag, index, base_url):
    """
    단일 폼에서 정보를 추출
    
    Args:
        form_tag: BeautifulSoup form 태그 객체
        index (int): 폼 순서
        base_url (str): 기준 URL
        
    Returns:
        Dict: 폼 정보 딕셔너리
    """
    try:
        csrf_token = _find_csrf_token(form_tag)
        
        return {
            'type': 'form',
            'index': index,
            'action': _get_action_url(form_tag, base_url),
            'method': _get_method(form_tag),
            'enctype': _get_enctype(form_tag),
            'parameters': _extract_parameters(form_tag),
            'has_csrf_token': csrf_token is not None,
            'csrf_token': csrf_token,
            'form_info': _extract_form_metadata(form_tag),
            'raw_html': str(form_tag)
        }
    except Exception as e:
        logger.error(f"폼 #{index} 추출 중 오류: {str(e)}")
        raise  # 원본 예외 보존

def _get_action_url(form_tag, base_url):
    """폼의 action URL을 추출하고 절대 URL로 변환"""
    try:
        action = form_tag.get('action', '').strip()
        
        # action이 없거나 빈 문자열인 경우
        if not action:
            logger.debug("Form action 속성 없음 → base_url 사용")
            return base_url or ''
        
        # action이 '#'인 경우 (현재 페이지)
        if action == '#':
            logger.debug("Form action='#' → base_url 사용")
            return base_url or ''
        
        # 프로토콜 상대 URL (//example.com) 처리
        if action.startswith('//'):
            absolute_url = 'https:' + action
            logger.debug(f"프로토콜 상대 URL 변환: '{action}' → '{absolute_url}'")
            return absolute_url
        
        # action이 절대 URL인 경우 (http://, https://)
        if action.startswith(('http://', 'https://')):
            logger.debug(f"절대 URL action 사용: {action}")
            return action
        
        # 상대 URL을 절대 URL로 변환
        if base_url:
            absolute_url = urljoin(base_url, action)
            logger.debug(f"상대 URL 변환: '{action}' + '{base_url}' → '{absolute_url}'")
            return absolute_url
        else:
            logger.debug("base_url 없이 상대 action 그대로 사용")
            return action
            
    except Exception as e:
        logger.error(f"Action URL 추출 오류: {str(e)}")
        raise

def _get_method(form_tag):
    """폼의 HTTP 메서드를 추출"""
    try:
        method = form_tag.get('method', 'get').lower().strip()
        
        # 유효한 HTTP 메서드인지 확인
        valid_methods = ['get', 'post', 'put', 'delete', 'patch']
        if method not in valid_methods:
            logger.warning(f"알 수 없는 HTTP 메서드: {method}, 'get'으로 설정")
            method = 'get'
        
        return method
    except Exception as e:
        logger.error(f"HTTP 메서드 추출 오류: {str(e)}")
        raise

def _get_enctype(form_tag):
    """폼의 enctype(인코딩 타입)을 추출"""
    try:
        enctype = form_tag.get('enctype', 'application/x-www-form-urlencoded').strip()
        logger.debug(f"Form enctype: {enctype}")
        return enctype
    except Exception as e:
        logger.error(f"Enctype 추출 오류: {str(e)}")
        raise

def _extract_parameters(form_tag):
    """
    폼의 모든 입력 필드를 파라미터로 추출
    
    Returns:
        Dict: {파라미터명: 기본값} 또는 {파라미터명: [값1, 값2]} 형태
    """
    try:
        parameters = defaultdict(list)
        
        # input, textarea, select 태그 처리
        for element in form_tag.find_all(['input', 'textarea', 'select']):
            name = element.get('name', '').strip()
            if not name:  # name이 없는 필드는 제외
                continue
                
            input_type = element.get('type', 'text').lower()
            
            # 버튼 타입은 공격 벡터가 아니므로 제외
            if input_type in ['submit', 'button', 'reset', 'image']:
                logger.debug(f"버튼 타입 필드 제외: {name} (type: {input_type})")
                continue
            
            # 기본값 추출
            default_value = _get_default_value(element)
            parameters[name].append(default_value)
            logger.debug(f"파라미터 추가: {name} = {default_value}")
        
        # 리스트를 단일 값 또는 리스트로 변환
        result = {}
        for name, values in parameters.items():
            if len(values) == 1:
                result[name] = values[0]
            else:
                result[name] = values  # 중복 name (checkbox, radio 그룹)
                logger.debug(f"중복 파라미터: {name} = {values}")
        
        logger.debug(f"총 {len(result)}개 파라미터 추출됨")
        return result
        
    except Exception as e:
        logger.error(f"파라미터 추출 오류: {str(e)}")
        raise

def _get_default_value(element):
    """입력 필드의 기본값 추출"""
    try:
        tag_name = element.name.lower()
        
        if tag_name == 'input':
            input_type = element.get('type', 'text').lower()
            
            if input_type in ['checkbox', 'radio']:
                # checked 상태인 것만 값으로 사용
                value = element.get('value', 'on') if element.has_attr('checked') else ''
                logger.debug(f"{input_type} 필드 값: {value} (checked: {element.has_attr('checked')})")
                return value
            elif input_type == 'file':
                logger.debug("파일 필드 → 빈 값")
                return ''  # 파일 필드는 빈 값
            else:
                value = element.get('value', '')
                logger.debug(f"{input_type} 필드 값: {value}")
                return value
                
        elif tag_name == 'textarea':
            value = element.get_text(strip=True)
            logger.debug(f"textarea 값: {value}")
            return value
            
        elif tag_name == 'select':
            # 선택된 option 찾기
            selected_option = element.find('option', selected=True)
            if selected_option:
                value = selected_option.get('value', selected_option.get_text(strip=True))
                logger.debug(f"select 선택된 값: {value}")
                return value
            
            # 첫 번째 option이 기본값
            first_option = element.find('option')
            if first_option:
                value = first_option.get('value', first_option.get_text(strip=True))
                logger.debug(f"select 첫 번째 옵션 값: {value}")
                return value
            
            logger.debug("select 옵션 없음")
            return ''
            
        logger.debug(f"알 수 없는 태그: {tag_name}")
        return ''
        
    except Exception as e:
        logger.error(f"기본값 추출 오류 (element: {element}): {str(e)}")
        raise

def _find_csrf_token(form_tag):
    """CSRF 토큰 찾기"""
    try:
        csrf_patterns = [
            'csrf', 'token', '_token', 'authenticity_token',
            'csrfmiddlewaretoken', 'csrf_token', 'csrfToken',
            '_csrf', 'security_token', 'form_token', '__RequestVerificationToken'
        ]
        
        for input_tag in form_tag.find_all('input', type='hidden'):
            name = input_tag.get('name', '')
            if name and any(pattern in name.lower() for pattern in csrf_patterns):
                csrf_info = {
                    'name': name,
                    'value': input_tag.get('value', ''),
                    'type': 'hidden'
                }
                logger.debug(f"CSRF 토큰 발견: {csrf_info}")
                return csrf_info
        
        logger.debug("CSRF 토큰 없음")
        return None
        
    except Exception as e:
        logger.error(f"CSRF 토큰 검색 오류: {str(e)}")
        raise

def _extract_form_metadata(form_tag):
    """폼의 추가 메타데이터 추출"""
    try:
        metadata = {
            'id': form_tag.get('id', ''),
            'class': form_tag.get('class', []),
            'name': form_tag.get('name', ''),
            'target': form_tag.get('target', ''),
            'autocomplete': form_tag.get('autocomplete', ''),
            'novalidate': form_tag.has_attr('novalidate'),
            'accept_charset': form_tag.get('accept-charset', ''),
        }
        logger.debug(f"폼 메타데이터: {metadata}")
        return metadata
    except Exception as e:
        logger.error(f"메타데이터 추출 오류: {str(e)}")
        raise

def _detect_file_upload_form(form_data):
    """
    폼이 파일 업로드 폼인지 정확하게 판별
    
    Args:
        form_data (Dict): 폼 정보 딕셔너리
        
    Returns:
        bool: 파일 업로드 폼 여부
    """
    try:
        # 1. enctype 확인
        if 'multipart' in form_data.get('enctype', '').lower():
            return True
        
        # 2. 파라미터 이름 확인 (더 정확한 키워드)
        param_names = list(form_data.get('parameters', {}).keys())
        file_keywords = ['file', 'upload', 'attachment', 'document', 'image', 'photo', 'avatar']
        
        for param_name in param_names:
            if any(keyword in param_name.lower() for keyword in file_keywords):
                return True
        
        # 3. 원본 HTML에서 input type="file" 확인
        raw_html = form_data.get('raw_html', '').lower()
        if 'type="file"' in raw_html or "type='file'" in raw_html:
            return True
        
        return False
        
    except Exception as e:
        logger.error(f"파일 업로드 폼 감지 오류: {str(e)}")
        return False

# 편의 함수들
def extract_forms_from_html(html_string, base_url=None):
    """
    HTML 문자열에서 직접 폼 추출
    
    Args:
        html_string (str): HTML 문자열
        base_url (str): 기준 URL
        
    Returns:
        List[Dict]: 폼 정보 리스트
    """
    try:
        soup = BeautifulSoup(html_string, 'html.parser')
        return extract_forms(soup, base_url)
    except Exception as e:
        logger.error(f"HTML 파싱 오류: {str(e)}")
        raise

def get_form_summary(forms):
    """
    폼 추출 결과 요약 정보
    
    Args:
        forms (List[Dict]): extract_forms() 결과
        
    Returns:
        Dict: 요약 정보
    """
    try:
        if not forms:
            return {
                'total_forms': 0,
                'get_forms': 0,
                'post_forms': 0,
                'forms_with_csrf': 0,
                'file_upload_forms': 0,
                'unique_actions': []
            }
        
        # 파일 업로드 폼 감지 개선
        file_upload_forms = 0
        for form in forms:
            if _detect_file_upload_form(form):
                file_upload_forms += 1
                logger.debug(f"파일 업로드 폼 감지: {form.get('action', 'no-action')}")
        
        summary = {
            'total_forms': len(forms),
            'get_forms': len([f for f in forms if f.get('method') == 'get']),
            'post_forms': len([f for f in forms if f.get('method') == 'post']),
            'forms_with_csrf': len([f for f in forms if f.get('csrf_token')]),
            'file_upload_forms': file_upload_forms,
            'unique_actions': list(set(f.get('action', '') for f in forms if f.get('action')))
        }
        
        logger.info(f"폼 요약: {summary}")
        return summary
        
    except Exception as e:
        logger.error(f"폼 요약 생성 오류: {str(e)}")
        raise

# 테스트 코드
if __name__ == "__main__":
    from bs4 import BeautifulSoup
    
    print("=== Form Extractor 테스트 ===")
    
    # 테스트용 HTML (모든 케이스 포함)
    test_html = """
    <html>
        <body>
            <!-- 로그인 폼 (POST, CSRF 토큰 포함) -->
            <form id="loginForm" action="/login" method="post">
                <input type="hidden" name="csrf_token" value="abc123">
                <input type="text" name="username" placeholder="사용자명" required>
                <input type="password" name="password" placeholder="비밀번호" required>
                <input type="submit" value="로그인">
            </form>
            
            <!-- 파일 업로드 폼 (enctype 기반) -->
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="file" name="file" accept=".jpg,.png">
                <textarea name="description" rows="3" placeholder="설명"></textarea>
                <input type="submit" value="업로드">
            </form>
            
            <!-- 파일 업로드 폼 (name 기반) -->
            <form action="/profile" method="post">
                <input type="text" name="profile_pic">
                <input type="text" name="avatar_image">
                <input type="submit" value="저장">
            </form>
            
            <!-- 검색 폼 (GET) -->
            <form method="get" action="/search">
                <input type="text" name="q" placeholder="검색어">
                <select name="category">
                    <option value="all">전체</option>
                    <option value="news" selected>뉴스</option>
                    <option value="images">이미지</option>
                </select>
                <input type="submit" value="검색">
            </form>
            
            <!-- action 없는 폼 테스트 -->
            <form method="post">
                <input type="text" name="test" value="no_action">
                <input type="submit" value="제출">
            </form>
            
            <!-- 상대 URL action 테스트 -->
            <form action="./relative" method="get">
                <input type="text" name="rel" value="relative_test">
                <input type="submit" value="제출">
            </form>
            
            <!-- 프로토콜 상대 URL 테스트 -->
            <form action="//api.example.com/submit" method="post">
                <input type="text" name="data" value="protocol_relative">
                <input type="submit" value="제출">
            </form>
            
            <!-- action='#' 테스트 -->
            <form action="#" method="get">
                <input type="text" name="anchor" value="hash_action">
                <input type="submit" value="제출">
            </form>
        </body>
    </html>
    """
    
    try:
        # BeautifulSoup으로 파싱 (html_parser.py에서 받을 데이터)
        soup = BeautifulSoup(test_html, 'html.parser')
        base_url = "https://example.com/page"
        
        # 폼 추출 (main function)
        forms = extract_forms(soup, base_url)
        
        print(f"\n추출된 폼 개수: {len(forms)}")
        print("-" * 80)
        
        # 각 폼 정보 출력
        for form in forms:
            print(f"\n폼 #{form['index']}:")
            print(f"  Type: {form['type']}")
            print(f"  Action: {form['action']}")
            print(f"  Method: {form['method'].upper()}")
            print(f"  Enctype: {form['enctype']}")
            print(f"  Parameters: {form['parameters']}")
            print(f"  CSRF Token: {form['csrf_token']}")
            print(f"  Has CSRF: {form['has_csrf_token']}")
            print(f"  File Upload: {_detect_file_upload_form(form)}")
            print(f"  Form ID: {form['form_info']['id']}")
            print(f"  Raw HTML: {form['raw_html'][:80]}...")
        
        # 요약 정보
        print("\n" + "="*80)
        summary = get_form_summary(forms)
        print("폼 추출 요약:")
        for key, value in summary.items():
            print(f"  {key}: {value}")
            
    except Exception as e:
        print(f"❌ 테스트 중 오류 발생: {e}")
        import traceback
        traceback.print_exc()