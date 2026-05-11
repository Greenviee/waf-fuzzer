from __future__ import annotations

import asyncio
import json
import os

from core import AttackSurface
from core.queue_manager import QueueManager
from crawler.engine import CrawlConfig, CrawlerEngine
from crawler.session_manager import AuthConfig
from modules.bruteforce.request_parser import parse_raw_request
from modules.bruteforce.target_prep import (
    build_targeted_bruteforce_surface,
    prepare_bruteforce_surfaces,
)
from parsers.surface_builder import SurfaceBuilder


def _export_surfaces_json(surfaces: list[AttackSurface], output_path: str) -> None:
    payload = [surface.to_dict() for surface in surfaces]
    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)


async def resolve_surfaces(args, base_url: str, cookies: dict[str, str]) -> list[AttackSurface]:
    if args.type == "bruteforce":
        return await _resolve_bruteforce_surfaces(args, base_url, cookies)

    surfaces = await _resolve_crawled_surfaces(
        args=args,
        start_url=base_url,
        cookies=cookies,
    )
    if not surfaces:
        print("Crawler returned no attack surfaces. Exiting.")
        return []
    return surfaces


async def _resolve_crawled_surfaces(
    args,
    start_url: str,
    cookies: dict[str, str] | None = None,
) -> list[AttackSurface]:
    """
    크롤러(CrawlerEngine) → 큐(QueueManager) → 파서(SurfaceBuilder) 파이프라인을 실행하고
    파서가 만들어낸 AttackSurface 목록을 반환한다.
    """
    queue_manager = QueueManager()
    surfaces: list[AttackSurface] = []

    async def _collect(surface: AttackSurface) -> None:
        surfaces.append(surface)

    surface_builder = SurfaceBuilder(fuzzer_callback=_collect)
    crawler = CrawlerEngine(
        queue_manager=queue_manager,
        config=CrawlConfig(),
    )

    # CLI에서 전달받은 쿠키(-c 옵션)를 크롤러 세션에 주입
    if cookies:
        crawler.session_manager.set_cookies(cookies)

    try:
        login_ready = await _login_if_configured(args, crawler)
        if not login_ready:
            return []

        # 크롤러(생산자)와 파서(소비자)를 동시에 실행
        # crawler.start()가 종료 신호(sentinel=None)를 큐에 넣으면
        # surface_builder.consume_from_queue()가 루프를 빠져나와 완료
        await asyncio.gather(
            surface_builder.consume_from_queue(queue_manager),
            crawler.start(start_url),
        )
    except Exception as exc:
        print(f"Failed to crawl target URL {start_url}: {exc}")
        return []
    finally:
        # login 단계에서 조기 종료되면 crawler.start() context manager가
        # 실행되지 않아 세션이 남을 수 있으므로 여기서 항상 정리한다.
        try:
            await crawler.session_manager.close()
        except Exception:
            pass

    print(f"[*] Crawler mode: discovered {len(surfaces)} attack surface(s).")
    surfaces_output = (getattr(args, "surfaces_output", "") or "").strip()
    if surfaces_output:
        try:
            _export_surfaces_json(surfaces, surfaces_output)
            print(f"[*] Attack surfaces exported: {surfaces_output}")
        except OSError as exc:
            print(f"Failed to export attack surfaces JSON: {exc}")
    return surfaces


async def _login_if_configured(args, crawler: CrawlerEngine) -> bool:
    username = (args.username or "").strip()
    password = (args.password or "").strip()
    login_url = (args.login_url or "").strip()

    if not username and not password and not login_url:
        return True

    if not (username and password and login_url):
        print("Login requires --login-url, --username, and --password together.")
        return False

    auth_config = AuthConfig(
        login_url=login_url,
        username=username,
        password=password,
        username_field=args.username_field,
        password_field=args.password_field,
        csrf_token_name=args.csrf_field or None,
        submit_field=args.submit_field or None,
    )

    if not await crawler.session_manager.login(auth_config):
        print(f"Login failed: {login_url}")
        return False

    print(f"[*] Login succeeded: {login_url}")
    return True


async def _resolve_bruteforce_surfaces(
    args,
    base_url: str,
    cookies: dict[str, str],
) -> list[AttackSurface]:
    if args.bf_request_file:
        return _resolve_raw_request_mode(args, cookies)

    if args.bf_target_url:
        target_label = args.bf_target_param or args.bf_fuzz_param
        print(f"[*] Targeted URL mode: {args.bf_target_url} [{target_label}=FUZZ]")
        return [build_targeted_bruteforce_surface(args, cookies)]

    # 실제 크롤러로 표면을 수집한 뒤 bruteforce용으로 가공
    surfaces = await _resolve_crawled_surfaces(
        args=args,
        start_url=base_url,
        cookies=cookies,
    )
    surfaces = prepare_bruteforce_surfaces(surfaces, args)
    if not surfaces:
        print(
            "No suitable parser surfaces found for bruteforce mode. "
            "Use --bf-target-url or --bf-request-file."
        )
        return []
    print(f"[*] Parser mode: prepared {len(surfaces)} brute-force surface(s).")
    return surfaces


def _resolve_raw_request_mode(args, cookies: dict[str, str]) -> list[AttackSurface]:
    if not os.path.exists(args.bf_request_file):
        print(f"Request file not found: {args.bf_request_file}")
        return []
    try:
        surface = parse_raw_request(args.bf_request_file)
        # CLI cookies override request file cookies when provided.
        if cookies:
            surface.cookies.update(cookies)
    except (ValueError, OSError) as exc:
        print(f"Failed to parse request file: {exc}")
        return []

    print(f"[*] Raw request mode: {surface.description}")
    return [surface]
