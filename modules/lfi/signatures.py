import re

# 타겟 파일별 LFI/RCE 성공 여부를 확정 짓는 정규식 시그니처
LFI_SIGNATURES = {
    # 1. Linux 기본 시스템 파일 (/etc/passwd)
    "passwd": re.compile(r"root:[x*]?:0:0:", re.IGNORECASE),

    # 2. Windows 시스템 파일 (win.ini, boot.ini 등)
    "win.ini": re.compile(
        r"\[(extensions|fonts|mci extensions|files|boot loader)\]",
        re.IGNORECASE,
    ),

    # 3. Linux 확장 시스템 파일 (group, shadow, proc/environ, logs 등)
    "linux_sys": re.compile(
        r"("
        r"daemon:x:1:|bin:x:2:|sys:x:3:"
        r"|root:(?:\$6\$|\$1\$|\$5\$|\*|!)"
        r"|HTTP_USER_AGENT=|SERVER_SOFTWARE="
        r")",
        re.IGNORECASE,
    ),

    # 4. Hosts 파일
    "hosts": re.compile(r"\b127\.0\.0\.1\s+localhost\b", re.IGNORECASE),

    # 5. OS/커널 정보 파일
    "os_info": re.compile(
        r"(PRETTY_NAME=|Linux version \d\.\d|DISTRIB_ID=)",
        re.IGNORECASE,
    ),

    # 6. SSH 개인 키 파일
    "ssh_key": re.compile(
        r"-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----",
        re.IGNORECASE,
    ),

    # 7. 웹 서버 로그 파일
    "logs": re.compile(
        r"(\[notice\]|\[error\]|GET \/.*? HTTP\/1\.[01]|POST \/.*? HTTP\/1\.[01])",
        re.IGNORECASE,
    ),

    # 8. PHP Wrapper (Base64 인코딩)
    "php_base64": re.compile(r"PD9waH[A]?", re.IGNORECASE),

    # 9. PHP Wrapper (ROT13 암호화)
    "php_rot13": re.compile(r"<\?cuc", re.IGNORECASE),

    # 10. RCE (원격 코드 실행) 결과
    "rce_output": re.compile(r"(uid=\d+\(.*gid=\d+|Shell done !)", re.IGNORECASE),
}


LFI_ERROR_SIGNATURES = [
    # --- [PHP 계열 에러] ---
    # LFI의 80% 이상을 차지합니다.
    re.compile(r"Warning: include\(.*?\)", re.IGNORECASE),
    re.compile(r"Warning: require\(.*?\)", re.IGNORECASE),
    re.compile(r"Warning: include_once\(.*?\)", re.IGNORECASE),
    re.compile(r"Warning: require_once\(.*?\)", re.IGNORECASE),
    re.compile(r"Warning: file_get_contents\(.*?\)", re.IGNORECASE),
    re.compile(r"failed to open stream: No such file or directory", re.IGNORECASE),
    re.compile(r"failed to open stream: Permission denied", re.IGNORECASE),
    re.compile(r"open_basedir restriction in effect", re.IGNORECASE),
    re.compile(r"allow_url_include is disabled", re.IGNORECASE), # RCE 래퍼 시도 시 차단 에러

    # --- [Java / Tomcat 계열 에러] ---
    # Spring이나 톰캣 환경에서 흔히 발생합니다.
    re.compile(r"java\.io\.FileNotFoundException", re.IGNORECASE),
    re.compile(r"java\.lang\.Exception:\s*File not found", re.IGNORECASE),
    re.compile(r"org\.apache\.catalina\.core\.ApplicationDispatcher", re.IGNORECASE), # 톰캣 내부 에러

    # --- [Node.js / Python 계열 에러] ---
    re.compile(r"Error: ENOENT: no such file or directory", re.IGNORECASE), # Node.js
    re.compile(r"IOError: \[Errno 2\] No such file or directory", re.IGNORECASE), # Python 2
    re.compile(r"FileNotFoundError: \[Errno 2\] No such file or directory", re.IGNORECASE), # Python 3

    # --- [범용 / 운영체제 레벨 에러] ---
    re.compile(r"System\.IO\.FileNotFoundException", re.IGNORECASE), # .NET / C#
    re.compile(r"\[Errno 13\] Permission denied", re.IGNORECASE), # 일반적인 리눅스 권한 에러
]
