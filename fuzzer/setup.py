from __future__ import annotations

from core import AttackSurface
from modules.bruteforce.module import BruteforceModule
from modules.sqli.module import SQLiModule
from modules.xss.module import XSSModule


def select_modules(args) -> list:
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


def count_module_payloads(modules: list) -> int:
    return sum(len(module.get_payloads()) for module in modules)


def estimate_total_requests(surfaces: list[AttackSurface], modules: list) -> int:
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

