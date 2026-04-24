from __future__ import annotations

import string

from modules.base_module import BaseModule
from modules.bruteforce.analyzer import detect_login_success
from modules.bruteforce.payloads import (
    DEFAULT_WORDLIST_PATH,
    get_dictionary_payloads,
    get_true_bruteforce_payloads,
)

_FUZZ = "FUZZ"


class BruteforceModule(BaseModule):
    def __init__(
        self,
        *,
        wordlist_path: str = DEFAULT_WORDLIST_PATH,
        enable_mutation: bool = True,
        mutation_level: int = 1,
        enable_true_bruteforce: bool = False,
        bf_charset: str = string.ascii_lowercase + string.digits,
        bf_min_length: int = 1,
        bf_max_length: int = 3,
        max_dictionary_candidates: int = 0,
        max_true_bf_candidates: int = 0,
        success_keywords: list[str] | None = None,
        fail_keywords: list[str] | None = None,
        stop_on_first_success: bool = True,
    ):
        super().__init__("Brute Force")
        self.wordlist_path = wordlist_path
        self.enable_mutation = enable_mutation
        self.mutation_level = mutation_level
        self.enable_true_bruteforce = enable_true_bruteforce
        self.bf_charset = bf_charset
        self.bf_min_length = bf_min_length
        self.bf_max_length = bf_max_length
        self.max_dictionary_candidates = max_dictionary_candidates
        self.max_true_bf_candidates = max_true_bf_candidates
        self.stop_on_first_success = stop_on_first_success
        self.success_keywords = success_keywords or [
            "welcome",
            "dashboard",
            "logout",
            "log out",
            "my account",
            "로그아웃",
        ]
        self.fail_keywords = fail_keywords or [
            "invalid",
            "incorrect",
            "failed",
            "wrong password",
            "login failed",
            "try again",
            "실패",
            "잘못",
        ]

    def get_payloads(self):
        payloads = []
        # True-random mode is exclusive: skip dictionary payloads.
        if not self.enable_true_bruteforce:
            payloads = get_dictionary_payloads(
                wordlist_path=self.wordlist_path,
                enable_mutation=self.enable_mutation,
                mutation_level=self.mutation_level,
                max_candidates=self.max_dictionary_candidates,
            )
        if self.enable_true_bruteforce:
            payloads.extend(
                get_true_bruteforce_payloads(
                    charset=self.bf_charset,
                    min_length=self.bf_min_length,
                    max_length=self.bf_max_length,
                    max_candidates=self.max_true_bf_candidates,
                )
            )
        return payloads

    def get_target_parameters(self, surface, parameters):
        """
        Return only parameters whose value is the FUZZ marker in the surface.
        This makes the module generic: any parameter tagged FUZZ is the target,
        regardless of its name (password, otp, token, coupon_code, ...).
        """
        surface_params: dict = getattr(surface, "parameters", {}) or {}
        return [p for p in parameters if surface_params.get(p) == _FUZZ]

    def analyze(self, response, payload, elapsed_time, original_res=None) -> bool:
        print(f"[*] [{self.name}] Trying payload: {payload.value}")
        is_success, evidences = detect_login_success(
            response=response,
            payload=payload,
            original_res=original_res,
            success_keywords=self.success_keywords,
            fail_keywords=self.fail_keywords,
        )
        if is_success:
            print(f"[+] [{self.name}] Valid credential candidate: {payload.value}")
            for evidence in evidences:
                print(f"    -> {evidence}")
        return is_success
