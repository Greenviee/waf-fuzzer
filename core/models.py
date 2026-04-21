from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"


class ParamLocation(str, Enum):
    QUERY = "query"
    BODY_FORM = "body_form"
    BODY_JSON = "body_json"
    HEADER = "header"
    COOKIE = "cookie"


@dataclass(slots=True)
class AttackSurface:
    """
    Shared DTO between crawler/parser and fuzzer engine.
    """

    url: str
    method: HttpMethod = HttpMethod.GET
    param_location: ParamLocation = ParamLocation.QUERY
    parameters: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    source_url: str | None = None
    description: str | None = None


@dataclass(slots=True, frozen=True)
class Payload:
    """
    Structured payload metadata used by payload provider/reporter.
    """

    value: str
    attack_type: str
    risk_level: str


@dataclass(slots=True, frozen=True)
class FuzzingTask:
    """
    One concrete fuzzing unit generated from a surface.
    """

    surface: AttackSurface
    target_param: str
    payload: Payload
