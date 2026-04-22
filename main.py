"""
CLI entrypoint: parses arguments, loads attack modules, runs the fuzzer, exports reports.

Payloads and vulnerability checks are imported from ``test_dependencies`` until the real
team modules are wired in (swap the import path only).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import warnings
from urllib.parse import parse_qsl, urlparse

from core import AttackSurface, HttpMethod, ParamLocation
from fuzzer import FuzzerEngine
from fuzzer.request_builder import build_and_send_request
from modules.sqli.module import SQLiModule
from modules.xss.analyzer import XSSModule
from reporter import ReportGenerator


def _parse_cookies(raw: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for item in raw.split(";"):
        item = item.strip()
        if not item or "=" not in item:
            continue
        name, value = item.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


def _select_modules(args) -> list:
    sqli_module = SQLiModule(
        enable_case_bypass=args.evasion_case,
        enable_null_byte_bypass=args.evasion_null_byte,
        enable_keyword_split_bypass=args.evasion_keyword_split,
        enable_double_url_encoding=args.evasion_double_url,
        enable_unicode_escape=args.evasion_unicode,
    )
    xss_module = XSSModule()

    if args.type == "sqli":
        return [sqli_module]
    if args.type == "xss":
        return [xss_module]
    if args.type == "all":
        return [sqli_module, xss_module]
    return []


def _count_module_payloads(modules: list) -> int:
    return sum(len(module.get_payloads()) for module in modules)


async def _request_sender(session, surface, parameter, payload):
    payload_value = getattr(payload, "value", str(payload))
    return await build_and_send_request(session, surface, parameter, payload_value)


def _count_surface_params(surface: AttackSurface) -> int:
    params = getattr(surface, "parameters", None)
    if params is None:
        return 0
    if isinstance(params, dict):
        return len(params)
    return len(tuple(params))


def _estimate_total_requests(surfaces: list[AttackSurface], modules: list) -> int:
    total = 0
    for surface in surfaces:
        param_count = _count_surface_params(surface)
        for module in modules:
            total += param_count * len(module.get_payloads())
    return total


async def _progress_printer(engine: FuzzerEngine, total_requests: int, scan_task: asyncio.Task) -> None:
    total = max(total_requests, 1)
    while not scan_task.done():
        completed = min(engine.stats.completed, total)
        percent = (completed / total) * 100
        print(f"\rProgress: {percent:6.2f}% ({completed}/{total})", end="", flush=True)
        await asyncio.sleep(0.2)

    completed = min(engine.stats.completed, total)
    percent = (completed / total) * 100
    print(f"\rProgress: {percent:6.2f}% ({completed}/{total})", end="", flush=True)
    print()


async def main() -> None:
    parser = argparse.ArgumentParser(description="WAF Fuzzer - integrated web vulnerability scanner CLI")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. http://example.com/vuln/?id=1)")
    parser.add_argument("-r", "--rps", type=int, default=5, help="Target requests per second throttle (default: 5)")
    parser.add_argument(
        "-c",
        "--cookie",
        type=str,
        default="",
        help="Cookie header value (e.g. 'PHPSESSID=abc; security=low')",
    )
    parser.add_argument("-o", "--output", type=str, default="scan_report.json", help="JSON report output path")
    parser.add_argument(
        "-t",
        "--type",
        type=str,
        default="all",
        choices=["sqli", "xss", "all"],
        help="Attack category to run (default: all)",
    )
    parser.add_argument(
        "--evasion-case",
        action="store_true",
        help="Enable case alternation bypass variants",
    )
    parser.add_argument(
        "--evasion-null-byte",
        action="store_true",
        help="Enable null-byte bypass variants",
    )
    parser.add_argument(
        "--evasion-keyword-split",
        action="store_true",
        help="Enable SQL keyword split bypass variants",
    )
    parser.add_argument(
        "--evasion-double-url",
        action="store_true",
        help="Enable double URL encoding variants",
    )
    parser.add_argument(
        "--evasion-unicode",
        action="store_true",
        help="Enable unicode escape variants",
    )

    args = parser.parse_args()

    parsed = urlparse(args.url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query_params = dict(parse_qsl(parsed.query))
    if not query_params:
        query_params = {"id": "1"}

    cookies = _parse_cookies(args.cookie) if args.cookie else {}

    surface = AttackSurface(
        url=base_url,
        method=HttpMethod.GET,
        param_location=ParamLocation.QUERY,
        parameters=query_params,
        cookies=cookies,
    )

    selected_modules = _select_modules(args)
    if not selected_modules:
        print(f"No modules registered for attack type {args.type!r}. Exiting.")
        return
    payload_count = _count_module_payloads(selected_modules)
    if payload_count == 0:
        print("No payloads loaded for selected modules. Exiting.")
        return

    delay = (1.0 / args.rps) if args.rps > 0 else 0.0
    concurrency = max(1, args.rps)
    surfaces = [surface]
    total_requests = _estimate_total_requests(surfaces, selected_modules)

    print("=" * 60)
    print(f"Target URL:     {base_url}")
    print(f"Parameters:     {list(query_params.keys())}")
    print(f"Attack type:    {args.type}")
    print(f"Module count:   {len(selected_modules)}")
    print(f"Payload count:  {payload_count}")
    print(f"Total requests: {total_requests}")
    print(
        "Evasions:       space,url"
        + (",case" if args.evasion_case else "")
        + (",null-byte" if args.evasion_null_byte else "")
        + (",keyword-split" if args.evasion_keyword_split else "")
        + (",double-url" if args.evasion_double_url else "")
        + (",unicode" if args.evasion_unicode else "")
    )
    print(f"Throttle (rps): {args.rps} (delay {delay:.3f}s)")
    print("=" * 60 + "\n")

    engine = FuzzerEngine(
        max_concurrent_requests=concurrency,
        worker_count=concurrency,  # kept for legacy mode compatibility
        modules=selected_modules,
        concurrency_per_module=concurrency,
        delay=delay,
    )

    scan_task = asyncio.create_task(
        engine.run_with_attack_modules(
            surfaces=surfaces,
            request_sender=_request_sender,
        )
    )
    progress_task = asyncio.create_task(_progress_printer(engine, total_requests, scan_task))
    stats = await scan_task
    await progress_task

    reporter = ReportGenerator(stats=stats, findings=engine.findings)
    reporter.print_cli_report()
    reporter.export_to_json(args.output)


if __name__ == "__main__":
    if sys.platform == "win32":
        # Suppress asyncio Windows loop policy deprecation noise on Python 3.13+.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
