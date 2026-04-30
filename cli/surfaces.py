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
        return _resolve_bruteforce_surfaces(args, base_url, cookies)

    surfaces = await _resolve_crawled_surfaces(start_url=base_url)
    if not surfaces:
        print("Crawler returned no attack surfaces. Exiting.")
        return []
    return surfaces


async def _resolve_crawled_surfaces(start_url: str) -> list[AttackSurface]:
    queue_manager = QueueManager()
    surfaces: list[AttackSurface] = []

    async def _collect(surface: AttackSurface) -> None:
        surfaces.append(surface)

    surface_builder = SurfaceBuilder(fuzzer_callback=_collect)
    crawler = CrawlerEngine(
        queue_manager=queue_manager,
        config=CrawlConfig(),
    )

    try:
        await asyncio.gather(
            surface_builder.consume_from_queue(queue_manager),
            crawler.start(start_url),
        )
    except Exception as exc:
        print(f"Failed to crawl target URL {start_url}: {exc}")
        return []

    print(f"[*] Crawler mode: discovered {len(surfaces)} attack surface(s).")
    return surfaces


def _resolve_bruteforce_surfaces(
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

    surfaces = get_dvwa_mock_surfaces(base_url=base_url, cookies=cookies)
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

