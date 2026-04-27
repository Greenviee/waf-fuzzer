from __future__ import annotations

from modules.base_module import BaseModule
from modules.bruteforce.module import BruteforceModule
from modules.lfi.module import LFIModule
from modules.sqli.module import SQLiModule
from modules.xss.analyzer import XSSModule


def get_attack_modules(attack_type: str) -> list[BaseModule]:
    """
    Module factory for CLI/runtime selection.
    Add new module mappings here as modules grow.
    """
    factories: dict[str, type[BaseModule]] = {
        "sqli": SQLiModule,
        "xss": XSSModule,
        "bruteforce": BruteforceModule,
        "lfi": LFIModule,
    }
    if attack_type == "all":
        return [factory() for factory in factories.values()]
    factory = factories.get(attack_type)
    return [factory()] if factory else []
