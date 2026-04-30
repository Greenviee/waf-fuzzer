from __future__ import annotations

import asyncio
import os

from core import AttackSurface
from core.queue_manager import QueueManager
from crawler.engine import CrawlConfig, CrawlerEngine
from modules.bruteforce.request_parser import parse_raw_request
from modules.bruteforce.target_prep import (
    build_targeted_bruteforce_surface,
    prepare_bruteforce_surfaces,
)
from parsers.surface_builder import SurfaceBuilder


async def resolve_surfaces(args, base_url: str, cookies: dict[str, str]) -> list[AttackSurface]:
    if args.type == "bruteforce":
        return await _resolve_bruteforce_surfaces(args, base_url, cookies)

    surfaces = await _resolve_crawled_surfaces(start_url=base_url, cookies=cookies)
    if not surfaces:
        print("Crawler returned no attack surfaces. Exiting.")
        return []
    return surfaces


async def _resolve_crawled_surfaces(
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

    print(f"[*] Crawler mode: discovered {len(surfaces)} attack surface(s).")
    return surfaces


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
    surfaces = await _resolve_crawled_surfaces(start_url=base_url, cookies=cookies)
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
