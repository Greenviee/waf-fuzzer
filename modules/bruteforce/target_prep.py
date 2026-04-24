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
        "token",
        "code",
        "auth_code",
        "verification_code",
    ]
    for candidate in candidate_order:
        found = find_param_key(parameters, candidate)
        if found:
            return found

    username_key = find_param_key(parameters, username_param)
    skip_keys = {"login", "submit", "action", "btnlogin", "btnsubmit"}
    for key in parameters.keys():
        key_lower = key.lower()
        if key_lower in skip_keys:
            continue
        if username_key and key == username_key:
            continue
        return key

    return next(iter(parameters.keys()), None)


def prepare_bruteforce_surfaces(
    surfaces: list[AttackSurface],
    args,
) -> list[AttackSurface]:
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

