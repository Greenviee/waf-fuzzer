from __future__ import annotations

import argparse
import os


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="WAF Fuzzer - integrated web vulnerability scanner CLI"
    )
    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="DVWA base URL (e.g. http://127.0.0.1/DVWA)",
    )
    parser.add_argument(
        "-r",
        "--rps",
        type=int,
        default=100,
        help="Target requests per second throttle (default: 100)",
    )
    parser.add_argument(
        "-c",
        "--cookie",
        type=str,
        default="",
        help="Cookie header value (e.g. 'PHPSESSID=abc; security=low')",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="scan_report.json",
        help="JSON report output path",
    )
    parser.add_argument(
        "-t",
        "--type",
        type=str,
        default="all",
        choices=["sqli", "bruteforce", "lfi", "file_upload", "ssrf", "all"],
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
        "--bf-min-length",
        type=int,
        default=1,
        help="Minimum length for true random bruteforce mode",
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
    parser.add_argument(
        "--bf-stop-on-first-hit",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Stop bruteforce module after first verified credential hit (default: enabled)",
    )
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
        "--sqli-evasion-level",
        type=int,
        choices=[0, 1, 2, 3],
        default=0,
        help="evasion level: 0 (None), 1 (1 technique), 2 (2 techniques), 3 (3 techniques)"
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
    parser.add_argument(
        "--session-pool-size",
        type=int,
        default=3,
        help="Number of HTTP sessions to use in parallel (default: 3)",
    )
    parser.add_argument(
        "--lfi-evasion-level",
        type=int,
        choices=[0, 1, 2, 3],
        default=1,
        help=(
            "LFI payload mutation level "
            "(0=raw only, 1=url-encoding, 2=double+null-byte, 3=path/case bypass)"
        ),
    )
    parser.add_argument(
        "--ssrf-bypass-level",
        type=int,
        choices=[0, 1, 2],
        default=1,
        help="SSRF bypass mutation level (0=off, 1=path encode, 2=path+ip obfuscation)",
    )
    parser.add_argument(
        "--ssrf-include-oob",
        action="store_true",
        help="Include OOB/template SSRF payloads in runtime payload set",
    )
    return parser


def parse_arguments() -> argparse.Namespace:
    return build_parser().parse_args()

