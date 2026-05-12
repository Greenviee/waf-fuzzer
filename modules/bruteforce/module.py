from __future__ import annotations

import string

from modules.base_module import BaseModule
from modules.bruteforce.analyzer import detect_login_success
from modules.bruteforce.payloads import (
    DEFAULT_WORDLIST_PATH,
    get_dictionary_payloads,
    get_true_bruteforce_payloads,
)
from modules.bruteforce.target_prep import select_bruteforce_target_param

_FUZZ = "FUZZ"

# 브루트포스 후보로 판별할 URL 경로 키워드
_SENSITIVE_PATHS = {
    "/login", "/signin", "/sign-in", "/logon",
    "/admin", "/auth", "/authenticate",
    "/verify", "/brute", "/account", "/session",
    "/wp-login", "/wp-admin",
}

# 브루트포스 후보로 판별할 파라미터 이름 키워드
_PASSWORD_PARAMS = {
    "password", "passwd", "pass", "pwd",
    "otp", "pin", "passcode",
}


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
        stop_on_first_hit: bool = True,
        success_keywords: list[str] | None = None,
        fail_keywords: list[str] | None = None,
        username_param: str = "username",
        bf_target_param: str = "",
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
        self.stop_on_first_hit = stop_on_first_hit
        self.username_param = username_param
        self.bf_target_param = bf_target_param
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
        공격 대상 파라미터를 결정한다.

        Mode 1 (명시적): surface.parameters 에 FUZZ 마커가 있으면 그 파라미터만 반환.
                         --bf-target-url / --bf-request-file 경로가 여기에 해당한다.

        Mode 2 (휴리스틱): FUZZ 마커가 없을 때 크롤러가 수집한 raw surface 에서
                          URL 경로·파라미터 이름을 기준으로 브루트포스 후보를 자동 선별.
                          후보가 아니면 빈 리스트를 반환해 해당 surface 를 skip 한다.
        """
        surface_params: dict = getattr(surface, "parameters", {}) or {}

        # Mode 1: 명시적 FUZZ 마커 우선
        fuzz_params = [p for p in parameters if surface_params.get(p) == _FUZZ]
        if fuzz_params:
            return fuzz_params

        # Mode 2: 명시 타겟 파라미터 우선(--bf-target-param)
        # 사용자가 타겟 파라미터를 지정한 경우 URL/키워드 휴리스틱보다 우선 적용한다.
        if self.bf_target_param:
            explicit = select_bruteforce_target_param(
                surface_params,
                username_param=self.username_param,
                explicit_target=self.bf_target_param,
            )
            return [explicit] if explicit else []

        # Mode 3: 휴리스틱 자동 선별
        if not self._is_brute_candidate(surface):
            return []

        target = select_bruteforce_target_param(
            surface_params,
            username_param=self.username_param,
            explicit_target=self.bf_target_param,
        )
        return [target] if target else []

    def _is_brute_candidate(self, surface) -> bool:
        """URL 경로 또는 파라미터 이름 휴리스틱으로 브루트포스 대상 여부를 판별."""
        url = (getattr(surface, "url", "") or "").lower()
        if any(path in url for path in _SENSITIVE_PATHS):
            return True

        params = getattr(surface, "parameters", {}) or {}
        for key in params:
            if key.lower() in _PASSWORD_PARAMS:
                return True

        return False

    def analyze(self, response, payload, elapsed_time, original_res=None, requester=None) -> bool:
        is_success, _ = detect_login_success(
            response=response,
            payload=payload,
            original_res=original_res,
            success_keywords=self.success_keywords,
            fail_keywords=self.fail_keywords,
        )
        return is_success
