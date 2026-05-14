# Modular Web Scanner

웹 애플리케이션을 크롤링해 공격 표면(파라미터·폼 등)을 수집하고, 모듈형 퍼저 엔진으로 **SQLi, LFI, SSRF, 파일 업로드, 로그인 브루트포스** 등을 비동기로 수행하는 **통합 웹 취약점 스캐너 CLI**입니다.  
FastAPI 기반의 간단한 **웹 UI**로 스캔을 트리거하고 결과를 조회할 수 있습니다.

> **법적·윤리적 고지**  
> 본 도구는 **본인이 소유하거나 명시적 서면 허가를 받은 시스템**에서만 사용하세요. 무단 스캔은 불법일 수 있습니다. 교육·연구·침투 테스트 계약 범위 내에서만 사용하시기 바랍니다.

---

## 주요 기능

| 영역 | 설명 |
|------|------|
| **크롤러** | `CrawlerEngine`이 시작 URL부터 링크를 따라가며 `QueueManager`에 페이지를 넣고, 깊이·URL 수·지연·타임아웃·워커 수 등 `CrawlConfig`로 조절합니다. |
| **파서 / 공격 표면** | `SurfaceBuilder`가 큐에서 HTML을 소비해 `AttackSurface` 목록을 생성합니다. 결과는 `--surfaces-output`(기본 `attack_surfaces.json`)으로보낼 수 있습니다. |
| **URL 필터** | `URLFilter`로 크롤링 대상을 제한하고, `--exclude-urls`로 정규식 패턴 목록을 넘기면 크롤러·세션에 주입됩니다. |
| **인증** | `--login-url`, `--username`, `--password` 및 폼 필드명(`--username-field`, `--password-field`, `--csrf-field`, `--submit-field`)으로 로그인 후 크롤링할 수 있습니다. `-c` / `--cookie`로 세션 쿠키를 직접 줄 수도 있습니다. |
| **퍼저** | `FuzzerEngine`이 모듈별 페이로드를 큐에 넣고 `aiohttp`로 요청을 보냅니다. RPS(`-r`), 워커 수(`-w`, 0이면 자동), 세션 풀(`--session-pool-size`)로 부하를 조절합니다. |
| **모듈** | **SQLi**, **브루트포스**, **LFI**, **파일 업로드**, **SSRF** (`fuzzer/setup.py` 기준). `-t all`은 브루트포스를 제외한 나머지를 순차 실행합니다. |
| **리포트** | 콘솔 요약 + JSON (`-o`, 기본 `scan_report.json`). 중복 제거·정렬 등은 `reporter` 패키지에서 처리합니다. |
| **웹 UI** | `webapp/main.py` — FastAPI + 정적 `index.html`. 스캔 시작·상태·결과 JSON 조회 API 제공. |

---

## 요구 사항

- **Python 3.10+** 권장 (Windows에서는 Python 3.13+ `asyncio` 관련 경고 억제 코드가 `main.py`에 포함되어 있습니다.)
- 주요 서드파티 패키지(코드 기준): **`aiohttp`**, **`beautifulsoup4`**, **`fastapi`**, **`pydantic`**, **`uvicorn`**(웹 서버 실행용)

저장소에 `requirements.txt` / `pyproject.toml`이 없을 수 있으므로, 아래는 참고용 한 줄 예시입니다.

```bash
pip install aiohttp beautifulsoup4 lxml fastapi pydantic uvicorn
```

---

## 설치·실행

저장소 루트에서:

```bash
# CLI 스캔
python main.py -u http://127.0.0.1/DVWA -t all
```

### 웹 UI

```bash
uvicorn webapp.main:app --reload --host 127.0.0.1 --port 8000
```

브라우저에서 `http://127.0.0.1:8000/` 로 접속합니다. (API 경로는 `webapp/main.py`의 FastAPI 라우트 정의를 참고하세요.)

---

## CLI 옵션 요약

| 옵션 | 설명 |
|------|------|
| `-u`, `--url` | **필수.** 스캔 대상 베이스 URL (예: DVWA 루트). |
| `-t`, `--type` | `sqli` \| `bruteforce` \| `lfi` \| `file_upload` \| `ssrf` \| `all` |
| `-r`, `--rps` | 초당 요청 상한(기본 100). |
| `-w`, `--workers` | 큐 워커 수(0이면 RPS 기반 자동). |
| `-c`, `--cookie` | 쿠키 문자열 (예: `PHPSESSID=...; security=low`). |
| `-o`, `--output` | 스캔 리포트 JSON 경로 (기본 `scan_report.json`). |
| `--surfaces-output` | 크롤링된 공격 표면 JSON (기본 `attack_surfaces.json`). |
| `--level` | SQLi / LFI / SSRF 회피 레벨을 한 번에 설정(SSRF는 최대 2). |
| `--exclude-urls` | 크롤·공격에서 제외할 URL **정규식** 패턴(여러 개 가능). |

**SQLi:** `--sqli-evasion-level`, `--sqli-time-based`, `--sqli-time-max`  
**LFI:** `--lfi-evasion-level`  
**SSRF:** `--ssrf-evasion-level`, `--ssrf-oob`  
**브루트포스:** 워드리스트·돌연변이·true-random 모드, `--bf-target-url` / `--bf-fuzz-param` / `--bf-method` / `--bf-extra-params` 등 (`cli/parser.py` 참고).

전체 옵션은 다음으로 확인할 수 있습니다.

```bash
python main.py -h
```

---

## 디렉터리 구조(개요)

```
├── main.py              # CLI 진입점 (asyncio)
├── cli/                 # 인자 파싱, 서피스 해석, 실행·출력
├── core/                # AttackSurface 등 공통 모델, 큐
├── crawler/             # 크롤러 엔진, 세션, URL 필터
├── parsers/             # HTML 파싱, 링크·폼 추출, SurfaceBuilder
├── fuzzer/              # FuzzerEngine, 요청 빌더
├── modules/             # sqli, lfi, ssrf, file_upload, bruteforce 등
├── config/payloads/    # 모듈별 페이로드·워드리스트
├── reporter/            # 리포트 생성·중복 제거
├── webapp/              # FastAPI + static UI
└── utils/               # 로거, 뮤테이터 등
```

---


---

## 라이선스

(프로젝트에 `LICENSE` 파일이 있으면 해당 내용을 따르고, 없다면 팀/조직 정책에 맞게 추가하세요.)
