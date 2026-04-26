"""
Form Extractor Module for Web Vulnerability Scanner
BeautifulSoup 객체에서 폼 정보를 추출하여 정형화된 데이터로 반환
모든 개선사항 반영: 타입 호환성, 성능 최적화, 메모리 효율성
"""

from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Any, Tuple
from typing_extensions import TypedDict, NotRequired

# 로깅 설정 (성능 최적화)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 상수 정의 (dataclass로 개선)
@dataclass
class FormExtractorConfig:
    """폼 추출기 설정 (런타임 변경 가능)"""
    
    # CSRF 토큰 패턴 (핵심만 선별)
    csrf_patterns: List[str] = field(default_factory=lambda: [
        'csrf_token', 'authenticity_token', 'csrfmiddlewaretoken',
        '_token', '_csrf', '__RequestVerificationToken',
        'security_token', 'form_token', '_wpnonce'
    ])
    
    # 제외할 입력 타입들
    excluded_input_types: set = field(default_factory=lambda: {
        'submit', 'button', 'reset', 'image'
    })
    
    # 파일 업로드 관련 키워드 (필수만)
    file_upload_keywords: List[str] = field(default_factory=lambda: [
        'file', 'upload', 'attachment', 'document', 
        'image', 'photo', 'avatar'
    ])
    
    # 파일 업로드 enctype
    file_upload_enctypes: List[str] = field(default_factory=lambda: [
        'multipart/form-data'
    ])
    
    # 유효한 HTTP 메서드
    valid_http_methods: List[str] = field(default_factory=lambda: [
        'get', 'post', 'put', 'delete', 'patch'
    ])
    
    # raw_html 최대 크기 설정
    max_raw_html_size: int = 10 * 1024  # 10KB
    truncation_suffix: str = '...'
    
    # 기본 enctype
    default_enctype: str = 'application/x-www-form-urlencoded'
    
    # 위험도 키워드
    risk_keywords: Dict[str, List[str]] = field(default_factory=lambda: {
        'high': ['password', 'passwd', 'pwd', 'admin', 'root', 'login', 'auth'],
        'medium': ['email', 'user', 'username', 'credit', 'payment', 'card'],
        'low': ['search', 'query', 'comment', 'message', 'feedback']
    })
    
    @classmethod
    def for_testing(cls) -> 'FormExtractorConfig':
        """테스트용 간소화된 설정"""
        return cls(
            csrf_patterns=['csrf_token', '_token'],
            max_raw_html_size=100,
            truncation_suffix='...'
        )
    
    @property
    def suffix_byte_length(self) -> int:
        """suffix의 바이트 길이"""
        return len(self.truncation_suffix.encode('utf-8'))

# TypedDict 정의 (NotRequired 사용)
class CSRFTokenInfo(TypedDict):
    """CSRF 토큰 정보"""
    name: str
    value: str
    type: str

class FormMetadata(TypedDict):
    """폼 메타데이터"""
    id: str
    class_: List[str]
    name: str
    target: str
    autocomplete: str
    novalidate: bool
    accept_charset: str

class FormInfo(TypedDict):
    """폼 정보 타입 정의 (선택적 필드 포함)"""
    # 필수 필드
    type: str
    index: int
    action: str
    method: str
    enctype: str
    parameters: Dict[str, Union[str, List[str]]]
    has_csrf_token: bool
    form_info: FormMetadata
    raw_html: str
    
    # 선택적 필드
    csrf_token: NotRequired[Optional[CSRFTokenInfo]]
    is_file_upload: NotRequired[bool]
    risk_level: NotRequired[str]
    button_count: NotRequired[int]

# 베이스 클래스
class BaseExtractor(ABC):
    """추출기 베이스 클래스"""
    
    def __init__(self, soup: BeautifulSoup, base_url: Optional[str] = None):
        self.soup = soup
        self.base_url = base_url
    
    @abstractmethod
    def extract(self) -> List[Any]:
        """추출 메서드 (하위 클래스에서 구현)"""
        pass

class FormExtractor(BaseExtractor):
    """HTML에서 폼 정보를 추출하여 정형화된 데이터로 반환하는 클래스"""
    
    def __init__(self, 
                 soup: BeautifulSoup, 
                 base_url: Optional[str] = None,
                 config: Optional[FormExtractorConfig] = None):
        """
        FormExtractor 초기화
        
        Args:
            soup (BeautifulSoup): 파싱된 HTML 객체
            base_url (str, optional): 상대 URL 해석용 기준 URL
            config (FormExtractorConfig, optional): 설정 객체
        """
        super().__init__(soup, base_url)
        self.config = config or FormExtractorConfig()

    def extract(self) -> List[FormInfo]:
        """베이스 클래스 인터페이스 구현"""
        return self.extract_forms()

    def extract_forms(self) -> List[FormInfo]:
        """
        BeautifulSoup 객체에서 폼 정보를 추출
        
        Returns:
            List[FormInfo]: 폼 정보 TypedDict 리스트
        """
        try:
            forms: List[FormInfo] = []
            form_tags = self.soup.find_all('form')
            
            if not form_tags:
                logger.info("추출할 폼이 없습니다.")
                return forms
                
            logger.info("폼 %d개 발견", len(form_tags))
            
            for i, form_tag in enumerate(form_tags):
                form_data = self._extract_single_form(form_tag, i)
                forms.append(form_data)
            
            logger.info("폼 추출 완료: %d개", len(forms))
            return forms
            
        except Exception as e:
            logger.error("폼 추출 중 오류 발생: %s", str(e))
            raise

    def _extract_single_form(self, form_tag, index: int) -> FormInfo:
        """
        단일 폼에서 정보를 추출 (메모리 효율성 개선)
        
        Args:
            form_tag: BeautifulSoup form 태그 객체
            index (int): 폼 순서
            
        Returns:
            FormInfo: 폼 정보 TypedDict
        """
        try:
            # 기본 정보 추출
            action = self._get_action_url(form_tag)
            method = self._get_method(form_tag)
            enctype = self._get_enctype(form_tag)
            
            # 파라미터 및 버튼 추출 (메모리 효율적)
            parameters, button_count = self._extract_parameters_and_buttons_efficient(form_tag)
            
            # CSRF 토큰 검사
            csrf_token = self._find_csrf_token(form_tag)
            
            # 파일 업로드 여부 판별
            is_file_upload = self._detect_file_upload(form_tag, enctype, parameters)
            
            # 위험도 평가
            risk_level = self._assess_risk_level(form_tag, parameters)
            
            # raw_html 크기 제한 적용
            raw_html = self._get_limited_raw_html(form_tag)
            
            # TypedDict 생성
            form_data: FormInfo = {
                'type': 'form',
                'index': index,
                'action': action,
                'method': method,
                'enctype': enctype,
                'parameters': parameters,
                'has_csrf_token': csrf_token is not None,
                'form_info': self._extract_form_metadata(form_tag),
                'raw_html': raw_html,
                # 선택적 필드들
                'csrf_token': csrf_token,
                'is_file_upload': is_file_upload,
                'risk_level': risk_level,
                'button_count': button_count
            }
            
            # 성능 최적화된 로깅
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("폼 %d 추출 완료: %s %s", index, method.upper(), action)
            
            return form_data
            
        except Exception as e:
            logger.error("폼 #%d 추출 중 오류: %s", index, str(e))
            raise

    def _get_action_url(self, form_tag) -> str:
        """폼의 action URL을 추출하고 절대 URL로 변환 (예외 처리 최적화)"""
        action = form_tag.get('action', '').strip()
        
        # action이 없거나 빈 문자열인 경우
        if not action:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Form action 속성 없음 → base_url 사용")
            return self.base_url or ''
        
        # action이 '#'인 경우 (현재 페이지)
        if action == '#':
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Form action='#' → base_url 사용")
            return self.base_url or ''
        
        # 프로토콜 상대 URL (//example.com) 처리
        if action.startswith('//'):
            absolute_url = 'https:' + action
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("프로토콜 상대 URL 변환: %s → %s", action, absolute_url)
            return absolute_url
        
        # action이 절대 URL인 경우
        if action.startswith(('http://', 'https://')):
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("절대 URL action 사용: %s", action)
            return action
        
        # 상대 URL을 절대 URL로 변환
        if self.base_url:
            absolute_url = urljoin(self.base_url, action)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("상대 URL 변환: %s + %s → %s", action, self.base_url, absolute_url)
            return absolute_url
        else:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("base_url 없이 상대 action 그대로 사용")
            return action

    def _get_method(self, form_tag) -> str:
        """폼의 HTTP 메서드를 추출 (간단한 로직, 예외 처리 제거)"""
        method = form_tag.get('method', 'get').lower().strip()
        
        if method not in self.config.valid_http_methods:
            logger.warning("알 수 없는 HTTP 메서드: %s, 'get'으로 설정", method)
            method = 'get'
        
        return method

    def _get_enctype(self, form_tag) -> str:
        """폼의 enctype 추출 (간단화)"""
        enctype = form_tag.get('enctype', self.config.default_enctype).strip()
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Form enctype: %s", enctype)
        return enctype

    def _extract_parameters_and_buttons_efficient(self, form_tag) -> Tuple[Dict[str, Union[str, List[str]]], int]:
        """
        메모리 효율적인 파라미터 및 버튼 추출
        
        Returns:
            Tuple: (parameters, button_count)
        """
        parameters: Dict[str, Union[str, List[str]]] = {}
        button_count = 0
        
        # input, textarea, select, button 태그 처리
        for element in form_tag.find_all(['input', 'textarea', 'select', 'button']):
            element_type = element.get('type', 'text' if element.name == 'input' else element.name).lower()
            
            # 버튼 개수 카운트 (모든 종류의 버튼)
            if (element.name == 'button' or 
                element_type in self.config.excluded_input_types):
                button_count += 1
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("버튼 발견: %s type='%s'", element.name, element_type)
                continue  # 버튼은 파라미터에서 제외
            
            name = element.get('name', '').strip()
            if not name:  # name이 없는 필드는 제외
                continue
            
            # 기본값 추출
            default_value = self._get_default_value(element)
            
            # 메모리 효율적인 파라미터 저장
            if name in parameters:
                # 이미 존재하는 경우 리스트로 변환 또는 추가
                current = parameters[name]
                if isinstance(current, list):
                    current.append(default_value)
                else:
                    parameters[name] = [current, default_value]
            else:
                # 첫 번째 값은 문자열로 저장
                parameters[name] = default_value
            
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("파라미터 추가: %s = %s (type: %s)", name, default_value, element_type)
        
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("총 %d개 파라미터, %d개 버튼 추출됨", len(parameters), button_count)
        
        return parameters, button_count

    def _get_default_value(self, element) -> str:
        """입력 필드의 기본값 추출 (예외 처리 최적화)"""
        tag_name = element.name.lower()
        
        if tag_name == 'input':
            input_type = element.get('type', 'text').lower()
            
            if input_type in ['checkbox', 'radio']:
                # 체크되지 않은 경우 빈 문자열 반환 (명시적 처리)
                if element.has_attr('checked'):
                    value = element.get('value', 'on')
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("%s 필드 체크됨: %s", input_type, value)
                    return value
                else:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("%s 필드 체크되지 않음 → 빈 값", input_type)
                    return ''  # 체크되지 않은 경우 빈 값
            elif input_type == 'file':
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("파일 필드 → 빈 값")
                return ''
            else:
                value = element.get('value', '')
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("%s 필드 값: %s", input_type, value)
                return value
                
        elif tag_name == 'textarea':
            value = element.get_text(strip=True)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("textarea 값: %s", value)
            return value
            
        elif tag_name == 'select':
            # 선택된 option 찾기
            selected_option = element.find('option', selected=True)
            if selected_option:
                value = selected_option.get('value', selected_option.get_text(strip=True))
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("select 선택된 값: %s", value)
                return value
            
            # 첫 번째 option이 기본값
            first_option = element.find('option')
            if first_option:
                value = first_option.get('value', first_option.get_text(strip=True))
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("select 첫 번째 옵션 값: %s", value)
                return value
            
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("select 옵션 없음")
            return ''
            
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("알 수 없는 태그: %s", tag_name)
        return ''

    def _find_csrf_token(self, form_tag) -> Optional[CSRFTokenInfo]:
        """CSRF 토큰 찾기 (정확성 개선, 예외 처리 최적화)"""
        for input_tag in form_tag.find_all('input', type='hidden'):
            name = input_tag.get('name', '')
            if not name:
                continue
            
            name_lower = name.lower()
            
            # 1. 정확히 일치하는 패턴 우선 검사
            for pattern in self.config.csrf_patterns:
                if name_lower == pattern.lower():
                    csrf_info: CSRFTokenInfo = {
                        'name': name,
                        'value': input_tag.get('value', ''),
                        'type': 'hidden'
                    }
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("CSRF 토큰 발견 (정확 매칭): %s", csrf_info)
                    return csrf_info
            
            # 2. 부분 문자열 매칭
            for pattern in self.config.csrf_patterns:
                if pattern.lower() in name_lower:
                    csrf_info: CSRFTokenInfo = {
                        'name': name,
                        'value': input_tag.get('value', ''),
                        'type': 'hidden'
                    }
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("CSRF 토큰 발견 (부분 매칭): %s", csrf_info)
                    return csrf_info
        
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("CSRF 토큰 없음")
        return None

    def _detect_file_upload(self, form_tag, enctype: str, parameters: Dict[str, Any]) -> bool:
        """파일 업로드 폼 감지 (예외 처리 최적화)"""
        # 1. enctype 확인
        if any(upload_type in enctype.lower() 
               for upload_type in self.config.file_upload_enctypes):
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("파일 업로드 감지 (enctype): %s", enctype)
            return True
        
        # 2. input type="file" 직접 확인
        file_inputs = form_tag.find_all('input', type='file')
        if file_inputs:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("파일 업로드 감지 (input type='file'): %d개", len(file_inputs))
            return True
        
        # 3. 파라미터 이름 키워드 확인
        for param_name in parameters.keys():
            param_lower = param_name.lower()
            if any(keyword in param_lower 
                   for keyword in self.config.file_upload_keywords):
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("파일 업로드 감지 (파라미터 이름): %s", param_name)
                return True
        
        return False

    def _assess_risk_level(self, form_tag, parameters: Dict[str, Any]) -> str:
        """위험도 평가 (예외 처리 최적화)"""
        # 파라미터 이름으로 위험도 판단
        param_names = ' '.join(parameters.keys()).lower()
        
        for risk_level, keywords in self.config.risk_keywords.items():
            if any(keyword in param_names for keyword in keywords):
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("위험도 %s 감지 (파라미터): %s", risk_level, keywords)
                return risk_level
        
        # 폼 속성으로 판단
        form_attrs = f"{form_tag.get('id', '')} {' '.join(form_tag.get('class', []))}"
        form_attrs = form_attrs.lower()
        
        for risk_level, keywords in self.config.risk_keywords.items():
            if any(keyword in form_attrs for keyword in keywords):
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("위험도 %s 감지 (속성): %s", risk_level, keywords)
                return risk_level
        
        return 'low'

    def _get_limited_raw_html(self, form_tag) -> str:
        """크기 제한된 raw HTML 반환 (매직 넘버 제거)"""
        try:
            raw_html = str(form_tag)
            
            # 크기 제한 적용
            raw_bytes = raw_html.encode('utf-8')
            if len(raw_bytes) > self.config.max_raw_html_size:
                # 바이트 단위로 자르고 suffix 추가
                truncated_bytes = raw_bytes[:self.config.max_raw_html_size - self.config.suffix_byte_length]
                raw_html = truncated_bytes.decode('utf-8', errors='ignore') + self.config.truncation_suffix
                
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("raw_html 크기 제한 적용: %d bytes", len(truncated_bytes))
            
            return raw_html
            
        except Exception as e:
            logger.error("raw_html 추출 오류: %s", str(e))
            # 안전한 fallback
            fallback = str(form_tag)[:100] + self.config.truncation_suffix
            return fallback

    def _extract_form_metadata(self, form_tag) -> FormMetadata:
        """폼의 메타데이터 추출 (예외 처리 최적화)"""
        metadata: FormMetadata = {
            'id': form_tag.get('id', ''),
            'class_': form_tag.get('class', []),
            'name': form_tag.get('name', ''),
            'target': form_tag.get('target', ''),
            'autocomplete': form_tag.get('autocomplete', ''),
            'novalidate': form_tag.has_attr('novalidate'),
            'accept_charset': form_tag.get('accept-charset', ''),
        }
        
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("폼 메타데이터: %s", metadata)
        
        return metadata

# 편의 함수들
def extract_forms(soup: BeautifulSoup, 
                 base_url: Optional[str] = None,
                 config: Optional[FormExtractorConfig] = None) -> List[FormInfo]:
    """
    BeautifulSoup 객체에서 폼 정보를 추출하는 편의 함수
    
    Args:
        soup (BeautifulSoup): 파싱된 HTML 객체
        base_url (str, optional): 기준 URL
        config (FormExtractorConfig, optional): 설정 객체
        
    Returns:
        List[FormInfo]: 폼 정보 TypedDict 리스트
    """
    extractor = FormExtractor(soup, base_url, config)
    return extractor.extract_forms()

def extract_forms_from_html(html_string: str, 
                           base_url: Optional[str] = None,
                           config: Optional[FormExtractorConfig] = None) -> List[FormInfo]:
    """
    HTML 문자열에서 직접 폼 추출
    
    Args:
        html_string (str): HTML 문자열
        base_url (str): 기준 URL
        config (FormExtractorConfig, optional): 설정 객체
        
    Returns:
        List[FormInfo]: 폼 정보 리스트
    """
    soup = BeautifulSoup(html_string, 'html.parser')
    return extract_forms(soup, base_url, config)

def get_form_summary(forms: List[FormInfo]) -> Dict[str, Any]:
    """
    폼 추출 결과 요약 정보 (예외 처리 최적화)
    
    Args:
        forms (List[FormInfo]): extract_forms() 결과
        
    Returns:
        Dict[str, Any]: 요약 정보
    """
    if not forms:
        return {
            'total_forms': 0,
            'get_forms': 0,
            'post_forms': 0,
            'forms_with_csrf': 0,
            'file_upload_forms': 0,
            'high_risk_forms': 0,
            'total_buttons': 0,
            'unique_actions': []
        }
    
    # 안전한 필드 접근
    summary = {
        'total_forms': len(forms),
        'get_forms': len([f for f in forms if f.get('method') == 'get']),
        'post_forms': len([f for f in forms if f.get('method') == 'post']),
        'forms_with_csrf': len([f for f in forms if f.get('csrf_token')]),
        'file_upload_forms': len([f for f in forms if f.get('is_file_upload', False)]),
        'high_risk_forms': len([f for f in forms if f.get('risk_level') == 'high']),
        'total_buttons': sum(f.get('button_count', 0) for f in forms),
        'unique_actions': list(set(f.get('action', '') for f in forms if f.get('action')))
    }
    
    logger.info("폼 요약 생성 완료: %d개 폼", summary['total_forms'])
    return summary

# 테스트용 설정 팩토리
def create_test_extractor(soup: BeautifulSoup, base_url: Optional[str] = None) -> FormExtractor:
    """테스트용 FormExtractor 생성"""
    test_config = FormExtractorConfig.for_testing()
    return FormExtractor(soup, base_url, test_config)

