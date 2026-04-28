from __future__ import annotations

from core import AttackSurface
from modules.bruteforce.module import BruteforceModule
from modules.sqli.module import SQLiModule
from modules.xss.analyzer import XSSModule


def select_modules(args) -> list:

    #필요한 모듈만 지연 생성 
    selected = []

    if args.type in ("sqli", "all"):
        sqli_module = SQLiModule(
            enable_case_bypass=args.evasion_case,
            enable_null_byte_bypass=args.evasion_null_byte,
            enable_keyword_split_bypass=args.evasion_keyword_split,
            enable_double_url_encoding=args.evasion_double_url,
            enable_unicode_escape=args.evasion_unicode,
            include_time_based=args.include_time_based,
            max_time_payloads=args.max_time_payloads,
            evasion_level=args.evasion_level,
        )
        selected.append(sqli_module)

    if args.type in ("xss", "all"):
        selected.append(XSSModule())

    if args.type in ("bruteforce", "all"):
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
        selected.append(bruteforce_module)

    return selected


def count_module_payloads(modules: list) -> int:
    #선택된 모듈들의 페이로드 총합 계산
    return sum(len(module.get_payloads()) for module in modules)


def estimate_total_requests(surfaces: list[AttackSurface], modules: list) -> int:
    # 각 모듈의 페이로드 개수를 미리 계산하여 반복적인 I/O 및 연산을 방지
    module_payload_counts = {id(m): len(m.get_payloads()) for m in modules}
    
    total = 0
    for surface in surfaces:
        all_params = tuple(getattr(surface, "parameters", {}).keys())
        for module in modules:
            module_params = all_params
            selector = getattr(module, "get_target_parameters", None)
            
            if callable(selector):
                selected = selector(surface, all_params)
                module_params = tuple(selected) if selected is not None else ()
            
            total += len(module_params) * module_payload_counts[id(module)]
            
    return total