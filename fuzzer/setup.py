from __future__ import annotations

from core import AttackSurface
from modules.bruteforce.module import BruteforceModule
from modules.lfi.module import LFIModule
from modules.file_upload.module import FileUploadModule
from modules.sqli.module import SQLiModule
from modules.ssrf.module import SSRFModule


def select_modules(args) -> list:
    selected = []

    if args.type in ("sqli", "all"):
        sqli_module = SQLiModule(
            include_time_based=args.sqli_time_based,
            max_time_payloads=args.sqli_time_max,
            evasion_level=args.sqli_evasion_level,
        )
        selected.append(sqli_module)

    if args.type == "bruteforce":
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
            stop_on_first_hit=args.bf_stop_on_first_hit,
            username_param=args.bf_username_param,
            bf_username=args.bf_username,
            bf_target_param=args.bf_target_param,
        )
        selected.append(bruteforce_module)

    if args.type in ("lfi", "all"):
        selected.append(LFIModule(evasion_level=args.lfi_evasion_level))

    if args.type in ("file_upload", "all"):
        selected.append(FileUploadModule())

    if args.type in ("ssrf", "all"):
        selected.append(
            SSRFModule(
                include_oob_templates=args.ssrf_oob,
                bypass_level=args.ssrf_evasion_level,
            )
        )

    return selected


def count_module_payloads(modules: list) -> int:
    total = 0
    for module in modules:
        # get_payload_count 메서드가 있으면 사용, 없으면 len() 시도
        if hasattr(module, "get_payload_count"):
            total += module.get_payload_count()
        else:
            total += len(module.get_payloads())
    return total


def estimate_total_requests(surfaces: list[AttackSurface], modules: list) -> int:

    #각 모듈의 페이로드 개수를 미리 계산하여 반복적인 I/O 및 연산을 방지
    module_payload_counts = {}
    for m in modules:
        if hasattr(m, "get_payload_count"):
            module_payload_counts[id(m)] = m.get_payload_count()
        else:
            module_payload_counts[id(m)] = len(m.get_payloads())
    
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