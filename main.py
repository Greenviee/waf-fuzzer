"""
CLI entrypoint for module-queue fuzzing with a mock parser stream.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import warnings
from typing import Any

from core import AttackSurface
from fuzzer import FuzzerEngine
from fuzzer.request_builder import build_and_send_request
from mock_parser import get_dvwa_mock_surfaces, run_mock_parser
from modules.base_module import BaseModule
from modules.sqli.payloads import get_sqli_payloads
from modules.xss.analyzer import XSSModule
from reporter import ReportGenerator

try:
    from modules.sqli import analyzer as sqli_analyzer
except ImportError as exc:
    raise RuntimeError("Cannot import SQLi analyzer module") from exc


def _parse_cookies(raw: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for item in raw.split(";"):
        item = item.strip()
        if not item or "=" not in item:
            continue
        name, value = item.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


class SQLiModuleAdapter(BaseModule):
    """
    Adapter for the current SQLi analyzer shape.
    Supports both bool and tuple(bool, evidence) analyzer return types.
    """

    def __init__(self) -> None:
        super().__init__("SQL Injection")
        self.error_signatures = [
            "sql syntax",
            "mysql_fetch",
            "native client",
            "ora-01756",
        ]

    def get_payloads(self) -> list[Any]:
        return get_sqli_payloads()

    def analyze(self, response, payload, elapsed_time: float, original_res=None) -> bool:
        result = sqli_analyzer.analyze(self, response, payload, elapsed_time, original_res)
        if isinstance(result, tuple):
            return bool(result[0])
        return bool(result)


def _select_modules(attack_type: str) -> list[BaseModule]:
    factories: dict[str, type[BaseModule]] = {
        "sqli": SQLiModuleAdapter,
        "xss": XSSModule,
    }
    if attack_type == "all":
        return [factory() for factory in factories.values()]
    factory = factories.get(attack_type)
    return [factory()] if factory else []


def _count_payloads(modules: list[BaseModule]) -> int:
    return sum(len(module.get_payloads()) for module in modules)


async def _module_request_sender(session, surface, parameter, payload):
    payload_value = getattr(payload, "value", str(payload))
    # print(f"[send] parameter={parameter!r} payload={payload_value!r}")
    return await build_and_send_request(session, surface, parameter, payload_value)


def _param_count(surface: AttackSurface) -> int:
    params = getattr(surface, "parameters", None)
    if params is None:
        return 0
    if isinstance(params, dict):
        return len(params)
    return len(tuple(params))


def _estimate_total_requests(surfaces: list[AttackSurface], modules: list[BaseModule]) -> int:
    total_payloads = _count_payloads(modules)
    return sum(_param_count(surface) * total_payloads for surface in surfaces)


async def _progress_printer(engine: FuzzerEngine, total_requests: int, stop: asyncio.Event) -> None:
    while not stop.is_set():
        stats = engine.stats
        total = max(1, total_requests)
        completed = min(stats.completed, total)
        percent = (completed / total) * 100
        print(f"\r[progress] {completed}/{total} ({percent:5.1f}%)", end="", flush=True)
        await asyncio.sleep(0.1)

    stats = engine.stats
    total = max(1, total_requests)
    completed = min(stats.completed, total)
    percent = (completed / total) * 100
    print(f"\r[progress] {completed}/{total} ({percent:5.1f}%)", end="", flush=True)
    print()


async def main() -> None:
    parser = argparse.ArgumentParser(description="WAF Fuzzer mock-parser integration CLI")
    parser.add_argument("-u", "--url", required=True, help="DVWA base URL (e.g. http://127.0.0.1/DVWA)")
    parser.add_argument("-r", "--rps", type=int, default=40, help="Target requests per second throttle (default: 40)")
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
        "--emit-delay",
        type=float,
        default=0.05,
        help="Delay between mock parser emissions in seconds (default: 0.05)",
    )

    args = parser.parse_args()

    cookies = _parse_cookies(args.cookie) if args.cookie else {}

    selected_modules = _select_modules(attack_type=args.type)
    if not selected_modules:
        print(f"No modules registered for attack type {args.type!r}. Exiting.")
        return
    payload_count = _count_payloads(selected_modules)

    delay = (1.0 / args.rps) if args.rps > 0 else 0.0
    concurrency = max(1, args.rps)
    preview_surfaces = get_dvwa_mock_surfaces(args.url, cookies=cookies)
    estimated_total_requests = _estimate_total_requests(preview_surfaces, selected_modules)

    print("=" * 60)
    print(f"DVWA base URL:  {args.url.rstrip('/')}")
    print(f"Attack type:    {args.type}")
    print(f"Module count:   {len(selected_modules)}")
    print(f"Payload count:  {payload_count}")
    print(f"Surface count:  {len(preview_surfaces)}")
    print(f"Est. requests:  {estimated_total_requests}")
    print(f"Throttle (rps): {args.rps} (delay {delay:.3f}s)")
    print(f"Emit delay:     {args.emit_delay:.3f}s")
    print("=" * 60 + "\n")

    engine = FuzzerEngine(
        max_concurrent_requests=concurrency,
        worker_count=concurrency,  # kept for legacy mode compatibility
        modules=selected_modules,
        concurrency_per_module=concurrency,
        delay=delay,
    )

    import aiohttp

    timeout = aiohttp.ClientTimeout(total=30.0)
    connector = aiohttp.TCPConnector(limit=concurrency * 2)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        progress_stop = asyncio.Event()
        progress_task = asyncio.create_task(
            _progress_printer(engine, total_requests=estimated_total_requests, stop=progress_stop)
        )
        await engine.start_module_mode(
            session=session,
            request_sender=_module_request_sender,
        )
        emitted_count = await run_mock_parser(
            engine,
            base_url=args.url,
            cookies=cookies,
            emit_delay=args.emit_delay,
            verbose=False,
        )
        await engine.stop_module_mode()
        progress_stop.set()
        await progress_task
        print(f"[main] mock parser emitted {emitted_count} surfaces")

    stats = engine.stats

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
