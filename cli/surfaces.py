from __future__ import annotations

import os

from core import AttackSurface
from mock_parser import get_dvwa_mock_surfaces
from modules.bruteforce.request_parser import parse_raw_request
from modules.bruteforce.target_prep import (
    build_targeted_bruteforce_surface,
    prepare_bruteforce_surfaces,
)


def resolve_surfaces(args, base_url: str, cookies: dict[str, str]) -> list[AttackSurface]:
    if args.type == "bruteforce":
        return _resolve_bruteforce_surfaces(args, base_url, cookies)

    surfaces = get_dvwa_mock_surfaces(base_url=base_url, cookies=cookies)
    if not surfaces:
        print("Mock parser returned no attack surfaces. Exiting.")
        return []
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

