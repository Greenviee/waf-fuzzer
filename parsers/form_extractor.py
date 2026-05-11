from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging
from typing import Dict, List, Optional, Union, Any
from typing_extensions import TypedDict, NotRequired

logger = logging.getLogger(__name__)

# 성능 최적화를 위한 상수 정의 (frozenset 사용)
CSRF_PATTERNS = frozenset({'csrf', 'token', 'authenticity', '_token', 'nonce'})
UPLOAD_ENCTYPES = frozenset({'multipart/form-data'})
RISK_KEYWORDS = {
    'high': frozenset({'password', 'passwd', 'pwd', 'admin', 'auth', 'login', 'pay'}),
    'medium': frozenset({'email', 'user', 'card', 'config'})
}


class CSRFTokenInfo(TypedDict):
    name: str
    value: str
    type: str


class FormInfo(TypedDict):
    type: str
    index: int
    action: str
    method: str
    enctype: str
    parameters: Dict[str, Union[str, List[str]]]
    has_csrf_token: bool
    raw_html: str
    csrf_token: NotRequired[Optional[CSRFTokenInfo]]
    is_file_upload: NotRequired[bool]
    risk_level: NotRequired[str]


def _get_attr_str(tag, attr: str, default: str = "") -> str:
    """BeautifulSoup의 list/str 속성 불일치 해결"""
    val = tag.get(attr, default)
    return " ".join(val) if isinstance(val, list) else str(val)


def _get_limited_raw_html(tag, max_bytes: int = 10240) -> str:
    """바이트 단위 안전 절삭"""
    raw_html = str(tag)
    raw_bytes = raw_html.encode('utf-8', errors='ignore')
    if len(raw_bytes) <= max_bytes:
        return raw_html
    return raw_bytes[:max_bytes].decode('utf-8', errors='ignore') + "..."


def extract_forms(
        html: Union[str, BeautifulSoup],
        base_url: Optional[str] = None,
        include_all_buttons: bool = True
) -> List[FormInfo]:
    """
    HTML에서 폼 정보를 추출하여 정형화된 데이터로 반환
    """
    soup = BeautifulSoup(html, 'html.parser') if isinstance(html, str) else html
    extracted_forms: List[FormInfo] = []

    for i, form in enumerate(soup.find_all('form')):
        try:
            # 1. 폼 기본 정보
            action_raw = _get_attr_str(form, 'action').strip()
            action = urljoin(base_url, action_raw) if base_url else action_raw
            method = _get_attr_str(form, 'method', 'get').lower()
            enctype = _get_attr_str(form, 'enctype', 'application/x-www-form-urlencoded').lower()

            # 2. 파라미터 수집
            params: Dict[str, Any] = {}
            has_file_input = False

            for el in form.find_all(['input', 'textarea', 'select', 'button']):
                name = _get_attr_str(el, 'name').strip()
                if not name: continue

                tag_name = el.name
                el_type = _get_attr_str(el, 'type').lower()
                val = ""

                if tag_name == 'select':
                    opt = el.find('option', selected=True) or el.find('option')
                    val = _get_attr_str(opt, 'value') if opt else ""
                elif tag_name == 'textarea':
                    val = el.get_text()
                elif tag_name == 'button' or el_type == 'submit':
                    if not include_all_buttons: continue
                    val = _get_attr_str(el, 'value')
                elif el_type == 'file':
                    has_file_input = True
                    val = ""
                elif el_type in ('checkbox', 'radio'):
                    if el.has_attr('checked'):
                        val = _get_attr_str(el, 'value', 'on')
                    else:
                        continue
                else:
                    val = _get_attr_str(el, 'value')

                # Multi-value 처리
                if name in params:
                    if isinstance(params[name], list):
                        params[name].append(val)
                    else:
                        params[name] = [params[name], val]
                else:
                    params[name] = val

            # 3. 보안 분석 (개선 사항 반영)
            csrf_info: Optional[CSRFTokenInfo] = None  # 타입 명시 반영
            param_names_lower = [str(k).lower() for k in params.keys()]
            param_str = " ".join(param_names_lower)  # Join 미리 수행 (효율화 반영)

            # CSRF 탐지
            for p_name, p_val in params.items():
                if any(pat in str(p_name).lower() for pat in CSRF_PATTERNS):
                    csrf_info = {'name': p_name, 'value': str(p_val), 'type': 'hidden'}
                    break

            # 위험도 산정
            risk_level = 'low'
            for level, keys in RISK_KEYWORDS.items():
                if any(k in param_str for k in keys):
                    risk_level = level
                    break

            # 4. 결과 저장
            extracted_forms.append({
                'type': 'form',
                'index': i,
                'action': action,
                'method': method if method in ('get', 'post', 'put', 'delete', 'patch') else 'get',
                'enctype': enctype,
                'parameters': params,
                'has_csrf_token': csrf_info is not None,
                'raw_html': _get_limited_raw_html(form),
                'csrf_token': csrf_info,
                'is_file_upload': has_file_input or (enctype in UPLOAD_ENCTYPES),
                'risk_level': risk_level
            })

        except (AttributeError, TypeError) as e:
            logger.warning("Form #%d parsing skipped: %s", i, e)
            continue

    return extracted_forms
