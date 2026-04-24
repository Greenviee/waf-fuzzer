"""
CLI entrypoint: parses arguments, loads attack modules, runs the fuzzer, exports reports.

Payloads and vulnerability checks are imported from ``test_dependencies`` until the real
team modules are wired in (swap the import path only).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import warnings

from core import AttackSurface, HttpMethod, ParamLocation
from fuzzer import FuzzerEngine
from fuzzer.request_builder import build_and_send_request
from mock_parser import get_dvwa_mock_surfaces
from modules.bruteforce.module import BruteforceModule
from modules.bruteforce.request_parser import parse_raw_request
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


def _parse_bf_length(raw: str, fallback_max: int) -> tuple[int, int]:
    """
    Parse brute-force length expression.
    Supported formats:
      - "8"   -> (1, 8)
      - "2~8" -> (2, 8)
    """
    text = (raw or "").strip()
    if not text:
        return 1, fallback_max

    if "~" in text:
        left, right = text.split("~", 1)
        min_len = int(left.strip())
        max_len = int(right.strip())
    else:
        min_len = 1
        max_len = int(text)

    if min_len < 1 or max_len < 1 or min_len > max_len:
        raise ValueError(f"Invalid --bf-length value: {raw!r}")
    return min_len, max_len


def _select_modules(args) -> list:
    sqli_module = SQLiModule(
        enable_case_bypass=args.evasion_case,
        enable_null_byte_bypass=args.evasion_null_byte,
        enable_keyword_split_bypass=args.evasion_keyword_split,
        enable_double_url_encoding=args.evasion_double_url,
        enable_unicode_escape=args.evasion_unicode,
        include_time_based=args.include_time_based,
        max_time_payloads=args.max_time_payloads,
    )
    xss_module = XSSModule()
    bruteforce_module = BruteforceModule(
        wordlist_path=args.bf_wordlist,
        enable_mutation=not args.bf_disable_mutation,
        mutation_level=args.bf_mutation_level,
        enable_true_bruteforce=args.bf_true_random,
        bf_charset=args.bf_charset,
        bf_min_length=args.bf_min_length,
        bf_max_length=args.bf_max_length,
        max_dictionary_candidates=args.bf_max_dictionary,
        max_true_bf_candidates=args.bf_max_true_random,
    )

    if args.type == "sqli":
        return [sqli_module]
    if args.type == "xss":
        return [xss_module]
    if args.type == "bruteforce":
        return [bruteforce_module]
    if args.type == "all":
        return [sqli_module, xss_module, bruteforce_module]
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


def _build_targeted_bruteforce_surface(args, cookies: dict[str, str]) -> AttackSurface:
    """
    Build a single AttackSurface from CLI options (--bf-target-url).
    All non-FUZZ parameters are sent verbatim; only the FUZZ-valued one is iterated.
    """
    method = HttpMethod.POST if args.bf_method == "POST" else HttpMethod.GET
    location = ParamLocation.BODY_FORM if method == HttpMethod.POST else ParamLocation.QUERY
    params: dict[str, str] = {}
    for pair in (args.bf_extra_params or []):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[k.strip()] = v.strip()

    target_param = args.bf_target_param or args.bf_fuzz_param
    params[target_param] = "FUZZ"
    params[args.bf_username_param] = args.bf_username

    return AttackSurface(
        url=args.bf_target_url.rstrip("/"),
        method=method,
        param_location=location,
        parameters=params,
        cookies=cookies,
        description=f"Targeted Brute Force [{target_param}=FUZZ]",
    )


def _find_param_key(parameters: dict[str, str], target_key: str) -> str | None:
    target = target_key.strip().lower()
    for key in parameters.keys():
        if key.lower() == target:
            return key
    return None


def _select_bruteforce_target_param(
    parameters: dict[str, str],
    *,
    username_param: str,
    explicit_target: str,
) -> str | None:
    if explicit_target:
        return _find_param_key(parameters, explicit_target)

    candidate_order = [
        "password",
        "passwd",
        "pass",
        "pwd",
        "otp",
        "pin",
        "token",
        "code",
        "auth_code",
        "verification_code",
    ]
    for candidate in candidate_order:
        found = _find_param_key(parameters, candidate)
        if found:
            return found

    username_key = _find_param_key(parameters, username_param)
    skip_keys = {"login", "submit", "action", "btnlogin", "btnsubmit"}
    for key in parameters.keys():
        key_lower = key.lower()
        if key_lower in skip_keys:
            continue
        if username_key and key == username_key:
            continue
        return key

    return next(iter(parameters.keys()), None)


def _prepare_bruteforce_surfaces(
    surfaces: list[AttackSurface],
    args,
) -> list[AttackSurface]:
    prepared: list[AttackSurface] = []
    for surface in surfaces:
        params = getattr(surface, "parameters", None)
        if not isinstance(params, dict) or not params:
            continue

        username_key = _find_param_key(params, args.bf_username_param)
        if username_key:
            params[username_key] = args.bf_username

        target_key = _select_bruteforce_target_param(
            params,
            username_param=args.bf_username_param,
            explicit_target=args.bf_target_param,
        )
        if not target_key:
            continue
        params[target_key] = "FUZZ"

        surface.description = (
            f"{surface.description or 'Bruteforce'} [target={target_key}, user={args.bf_username}]"
        )
        prepared.append(surface)

    return prepared


def _estimate_total_requests(surfaces: list[AttackSurface], modules: list) -> int:
    total = 0
    for surface in surfaces:
        all_params = tuple(getattr(surface, "parameters", {}).keys())
        for module in modules:
            module_params = all_params
            selector = getattr(module, "get_target_parameters", None)
            if callable(selector):
                selected = selector(surface, all_params)
                module_params = tuple(selected) if selected is not None else ()
            total += len(module_params) * len(module.get_payloads())
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
    parser.add_argument("-u", "--url", required=True, help="DVWA base URL (e.g. http://127.0.0.1/DVWA)")
    parser.add_argument("-r", "--rps", type=int, default=100, help="Target requests per second throttle (default: 100)")
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
        choices=["sqli", "xss", "bruteforce", "all"],
        help="Attack category to run (default: all)",
    )
    parser.add_argument(
        "--bf-wordlist",
        type=str,
        default=os.path.join("config", "payloads", "common_passwords.txt"),
        help="Bruteforce dictionary file path (absolute or relative)",
    )
    parser.add_argument(
        "--bf-disable-mutation",
        action="store_true",
        help="Disable password mutation in bruteforce dictionary mode",
    )
    parser.add_argument(
        "--bf-mutation-level",
        type=int,
        choices=[0, 1, 2, 3],
        default=1,
        help=(
            "Mutation intensity for bruteforce dictionary mode "
            "(0=none, 1=basic, 2=extended suffixes, 3=extended+leet)"
        ),
    )
    parser.add_argument(
        "--bf-true-random",
        action="store_true",
        help="Enable exclusive true-random bruteforce mode (dictionary disabled)",
    )
    parser.add_argument(
        "--bf-charset",
        type=str,
        default="abcdefghijklmnopqrstuvwxyz0123456789",
        help="Charset for true random bruteforce mode",
    )
    parser.add_argument(
        "--bf-max-length",
        type=int,
        default=3,
        help="Maximum length for true random bruteforce mode",
    )
    parser.add_argument(
        "--bf-length",
        type=str,
        default="",
        help=(
            "True-random brute-force length or range. "
            "Examples: --bf-length 8 (means 1~8), --bf-length 2~8. "
            "Overrides --bf-max-length."
        ),
    )
    parser.add_argument(
        "--bf-max-dictionary",
        type=int,
        default=0,
        help="Cap dictionary payload count (0=all)",
    )
    parser.add_argument(
        "--bf-max-true-random",
        type=int,
        default=0,
        help="Cap true random payload count (0=all)",
    )
    # --- Bruteforce surface source (choose one) ---
    parser.add_argument(
        "--bf-request-file",
        type=str,
        default="",
        metavar="FILE",
        help=(
            "Path to a raw HTTP request file (Burp-style). "
            "Mark the brute-force target parameter value with 'FUZZ'. "
            "Supports GET query strings and POST form-encoded / JSON bodies."
        ),
    )
    parser.add_argument(
        "--bf-target-url",
        type=str,
        default="",
        metavar="URL",
        help=(
            "Direct target URL for bruteforce (simple mode, no request file). "
            "Combine with --bf-fuzz-param and --bf-extra-params."
        ),
    )
    parser.add_argument(
        "--bf-method",
        type=str,
        choices=["GET", "POST"],
        default="GET",
        help="HTTP method used with --bf-target-url (default: GET)",
    )
    parser.add_argument(
        "--bf-fuzz-param",
        type=str,
        default="password",
        metavar="PARAM",
        help=(
            "Parameter name to brute-force when using --bf-target-url "
            "(its value is set to FUZZ automatically). Default: password"
        ),
    )
    parser.add_argument(
        "--bf-target-param",
        type=str,
        default="",
        metavar="PARAM",
        help=(
            "Force target parameter in parser/target-url modes. "
            "If omitted, bruteforce target parameter is auto-selected."
        ),
    )
    parser.add_argument(
        "--bf-username-param",
        type=str,
        default="username",
        metavar="PARAM",
        help="Parameter name to override with --bf-username (default: username)",
    )
    parser.add_argument(
        "--bf-username",
        type=str,
        default="admin",
        metavar="VALUE",
        help="Username value used in bruteforce mode (default: admin)",
    )
    parser.add_argument(
        "--bf-extra-params",
        type=str,
        nargs="*",
        default=[],
        metavar="KEY=VALUE",
        help=(
            "Additional fixed parameters sent alongside FUZZ when using --bf-target-url. "
            "Example: --bf-extra-params username=admin Login=Login"
        ),
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
    parser.add_argument(
        "--include-time-based",
        action="store_true",
        help="Include SQLi time/stacked payloads (much slower)",
    )
    parser.add_argument(
        "--max-time-payloads",
        type=int,
        default=0,
        help="Limit number of time/stacked payloads when enabled (0=all)",
    )

    args = parser.parse_args()
    try:
        args.bf_min_length, args.bf_max_length = _parse_bf_length(
            args.bf_length,
            args.bf_max_length,
        )
    except ValueError as exc:
        print(str(exc))
        return

    cookies = _parse_cookies(args.cookie) if args.cookie else {}
    base_url = args.url.rstrip("/")

    if args.type == "bruteforce":
        if args.bf_request_file:
            # Mode 1: raw HTTP request file — parses all params, FUZZ marks the target.
            if not os.path.exists(args.bf_request_file):
                print(f"Request file not found: {args.bf_request_file}")
                return
            try:
                surface = parse_raw_request(args.bf_request_file)
                # CLI cookies override (in case session cookie is newer than captured file)
                if cookies:
                    surface.cookies.update(cookies)
            except (ValueError, OSError) as exc:
                print(f"Failed to parse request file: {exc}")
                return
            print(f"[*] Raw request mode: {surface.description}")
            surfaces = [surface]
        elif args.bf_target_url:
            # Mode 2: simple URL + named param (GET/POST without extra params complexity)
            target_label = args.bf_target_param or args.bf_fuzz_param
            print(f"[*] Targeted URL mode: {args.bf_target_url} [{target_label}=FUZZ]")
            surfaces = [_build_targeted_bruteforce_surface(args, cookies)]
        else:
            # Mode 3: parser-provided surfaces; auto-select target parameter and override username.
            surfaces = get_dvwa_mock_surfaces(base_url=base_url, cookies=cookies)
            surfaces = _prepare_bruteforce_surfaces(surfaces, args)
            if not surfaces:
                print(
                    "No suitable parser surfaces found for bruteforce mode. "
                    "Use --bf-target-url or --bf-request-file."
                )
                return
            print(f"[*] Parser mode: prepared {len(surfaces)} brute-force surface(s).")
    else:
        surfaces = get_dvwa_mock_surfaces(base_url=base_url, cookies=cookies)
        if not surfaces:
            print("Mock parser returned no attack surfaces. Exiting.")
            return

    selected_modules = _select_modules(args)
    if not selected_modules:
        print(f"No modules registered for attack type {args.type!r}. Exiting.")
        return
    if args.type in ("bruteforce", "all") and not os.path.exists(args.bf_wordlist):
        print(f"Bruteforce wordlist not found: {args.bf_wordlist}")
        return
    payload_count = _count_module_payloads(selected_modules)
    if payload_count == 0:
        print("No payloads loaded for selected modules. Exiting.")
        return

    delay = (1.0 / args.rps) if args.rps > 0 else 0.0
    concurrency = max(1, args.rps)
    queue_workers = max(1, args.rps * 2)
    total_requests = _estimate_total_requests(surfaces, selected_modules)

    print("=" * 60)
    print(f"Target URL:     {base_url}")
    print(f"Surface count:  {len(surfaces)}")
    print(f"Attack type:    {args.type}")
    print(f"Module count:   {len(selected_modules)}")
    print(f"Payload count:  {payload_count}")
    print(
        "SQLi timing:    "
        + ("included" if args.include_time_based else "excluded (fast mode)")
        + (f", max={args.max_time_payloads}" if args.include_time_based else "")
    )
    print(f"Total requests: {total_requests}")
    print("Evasions:       off (mutator disabled)")
    print(f"Throttle (rps): {args.rps} (delay {delay:.3f}s)")
    print(f"Queue workers:  {queue_workers}")
    print("=" * 60 + "\n")

    engine = FuzzerEngine(
        max_concurrent_requests=concurrency,
        worker_count=queue_workers,  # queue consumption workers
        modules=selected_modules,
        concurrency_per_module=queue_workers,
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
