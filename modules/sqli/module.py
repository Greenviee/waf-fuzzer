from __future__ import annotations

from modules.base_module import BaseModule
from modules.sqli import analyzer as sqli_analyzer
from modules.sqli.payloads import get_sqli_payloads


class SQLiModule(BaseModule):
    """
    SQLi module wrapper.
    Keeps SQLi-specific wiring inside modules/sqli, not in main.py.
    """

    def __init__(self) -> None:
        super().__init__("SQL Injection")
        self.error_signatures = [
            "sql syntax",
            "mysql_fetch",
            "native client",
            "ora-01756",
        ]

    def get_payloads(self):
        return get_sqli_payloads()

    def analyze(self, response, payload, elapsed_time: float, original_res=None) -> bool:
        result = sqli_analyzer.analyze(self, response, payload, elapsed_time, original_res)
        if isinstance(result, tuple):
            return bool(result[0])
        return bool(result)
