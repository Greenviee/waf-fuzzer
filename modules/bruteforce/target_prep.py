from __future__ import annotations

from core import AttackSurface, HttpMethod, ParamLocation


def build_targeted_bruteforce_surface(args, cookies: dict[str, str]) -> AttackSurface:
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


def find_param_key(parameters: dict[str, str], target_key: str) -> str | None:
    target = target_key.strip().lower()
    for key in parameters.keys():
        if key.lower() == target:
            return key
    return None


def select_bruteforce_target_param(
    parameters: dict[str, str],
    *,
    username_param: str,
    explicit_target: str,
) -> str | None:
    if explicit_target:
        return find_param_key(parameters, explicit_target)

    candidate_order = [
        "password",
        "passwd",
        "pass",
        "pwd",
        "otp",
        "pin",
        "passcode",
    ]
    for candidate in candidate_order:
        found = find_param_key(parameters, candidate)
        if found:
            return found

    # Conservative mode:
    # do not brute-force ambiguous params when no explicit password-like key exists.
    return None


def prepare_bruteforce_surfaces(
    surfaces: list[AttackSurface],
    args,
) -> list[AttackSurface]:
    """
    레거시 헬퍼: 크롤된 표면에 FUZZ 마커를 미리 주입하는 방식.
    현재는 BruteforceModule.get_target_parameters 의 휴리스틱 모드를
    통해 모듈 내부에서 처리하므로, --bf-request-file 등 명시적 모드에서만 사용된다.
    """
    prepared: list[AttackSurface] = []
    for surface in surfaces:
        params = getattr(surface, "parameters", None)
        if not isinstance(params, dict) or not params:
            continue

        username_key = find_param_key(params, args.bf_username_param)
        if username_key:
            params[username_key] = args.bf_username

        target_key = select_bruteforce_target_param(
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


def apply_username_to_surfaces(
    surfaces: list[AttackSurface],
    *,
    username_param: str,
    username_value: str,
) -> list[AttackSurface]:
    """
    크롤 모드 브루트포스 전처리: 유저네임 파라미터 값만 고정하고,
    FUZZ 마킹이나 표면 필터링은 BruteforceModule.get_target_parameters 에 위임한다.
    parameters dict 가 없는 표면은 조용히 제외한다.
    """
    result: list[AttackSurface] = []
    for surface in surfaces:
        params = getattr(surface, "parameters", None)
        if not isinstance(params, dict) or not params:
            continue
        username_key = find_param_key(params, username_param)
        if username_key:
            params[username_key] = username_value
        result.append(surface)
    return result

