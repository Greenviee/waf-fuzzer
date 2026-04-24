from __future__ import annotations

import asyncio
import inspect
import logging
import time
from pathlib import Path
from typing import Any
from typing import Literal
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from cli.options import parse_cookies
from fuzzer import FuzzerEngine
from fuzzer.request_builder import build_and_send_request
from fuzzer.setup import estimate_total_requests
from mock_parser import get_dvwa_mock_surfaces
from modules.bruteforce.module import BruteforceModule
from modules.sqli.module import SQLiModule
from modules.xss.analyzer import XSSModule

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("waf-fuzzer.web")

app = FastAPI(
    title="WAF Fuzzer Dashboard API",
    description="Real scan backend bridged with existing CLI engine.",
    version="1.0.0",
)

# In-memory storage for demo purpose. Replace with DB/Redis in production.
scans_db: dict[str, dict[str, Any]] = {}


class ScanRequest(BaseModel):
    target_url: str = Field(..., min_length=1, max_length=2048)
    attack_type: Literal["all", "sqli", "xss", "bruteforce"] = "all"
    rps: int = Field(default=20, ge=1, le=10000)
    cookie: str = Field(default="")
    extra_options: list[dict[str, str]] = Field(default_factory=list)


def _coerce_option_value(raw: str) -> Any:
    value = raw.strip()
    if not value:
        return value
    lowered = value.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"none", "null"}:
        return None
    if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        return int(value)
    try:
        return float(value)
    except ValueError:
        return value


def _extract_module_kwargs(module_cls: type, user_options: dict[str, Any], aliases: list[str]) -> dict[str, Any]:
    valid_params = set(inspect.signature(module_cls.__init__).parameters)
    valid_params.discard("self")
    collected: dict[str, Any] = {}
    for key, value in user_options.items():
        if key in valid_params:
            collected[key] = value
            continue
        for alias in aliases:
            prefix = f"{alias}."
            if key.startswith(prefix):
                stripped = key[len(prefix) :]
                if stripped in valid_params:
                    collected[stripped] = value
                break
    return collected


def _build_attack_modules(attack_type: str, options: list[dict[str, str]]) -> list[Any]:
    option_map: dict[str, Any] = {}
    for row in options:
        key = str(row.get("key", "")).strip()
        if not key:
            continue
        option_map[key] = _coerce_option_value(str(row.get("value", "")))

    modules: list[Any] = []
    if attack_type in {"all", "sqli"}:
        sqli_kwargs = _extract_module_kwargs(SQLiModule, option_map, aliases=["sqli"])
        modules.append(SQLiModule(**sqli_kwargs))
    if attack_type in {"all", "xss"}:
        modules.append(XSSModule())
    if attack_type in {"all", "bruteforce"}:
        bruteforce_kwargs = _extract_module_kwargs(
            BruteforceModule,
            option_map,
            aliases=["bruteforce", "bf"],
        )
        modules.append(BruteforceModule(**bruteforce_kwargs))
    return modules


@app.post("/api/scan/start")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks) -> dict[str, str]:
    scan_id = str(uuid4())
    scans_db[scan_id] = {
        "status": "running",
        "progress": 0,
        "target": req.target_url,
        "type": req.attack_type,
        "rps": req.rps,
        "findings": [],
        "summary": {
            "total_requests": 0,
            "successful_findings": 0,
            "failed_requests": 0,
            "elapsed_time": 0.0,
        },
    }

    logger.info("=" * 56)
    logger.info(
        "Scan start id=%s target=%s attack_type=%s rps=%s",
        scan_id,
        req.target_url,
        req.attack_type,
        req.rps,
    )
    if req.cookie:
        logger.info("Cookie input received (%s chars)", len(req.cookie))
    logger.info("=" * 56)

    background_tasks.add_task(run_real_fuzzer_task, scan_id, req)
    return {"scan_id": scan_id, "message": "Scan started successfully"}


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str) -> dict[str, Any]:
    scan = scans_db.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return scan


async def run_real_fuzzer_task(scan_id: str, req: ScanRequest) -> None:
    try:
        cookies = parse_cookies(req.cookie) if req.cookie else {}
        surfaces = get_dvwa_mock_surfaces(base_url=req.target_url, cookies=cookies)
        modules = _build_attack_modules(req.attack_type, req.extra_options)
        started_at = time.monotonic()
        logger.info(
            "[%s] parser discovered %s surfaces, modules loaded=%s",
            scan_id,
            len(surfaces),
            len(modules),
        )

        if not surfaces or not modules:
            scans_db[scan_id]["progress"] = 100
            scans_db[scan_id]["status"] = "completed"
            scans_db[scan_id]["findings"] = []
            scans_db[scan_id]["summary"] = {
                "total_requests": 0,
                "successful_findings": 0,
                "failed_requests": 0,
                "elapsed_time": 0.0,
            }
            logger.warning("[%s] scan completed early (empty surfaces/modules)", scan_id)
            return

        total_requests = max(1, estimate_total_requests(surfaces, modules))
        delay = (1.0 / req.rps) if req.rps > 0 else 0.0
        queue_workers = max(1, req.rps * 2)

        engine = FuzzerEngine(
            max_concurrent_requests=max(1, req.rps),
            worker_count=queue_workers,
            modules=modules,
            concurrency_per_module=queue_workers,
            session_pool_size=3,
            delay=delay,
        )

        async def request_sender(session, surface, parameter, payload):
            payload_value = getattr(payload, "value", str(payload))
            logger.info(
                "[%s] [SEND] %s %s | param=%s | payload=%s",
                scan_id,
                getattr(surface.method, "value", str(surface.method)),
                surface.url,
                parameter,
                str(payload_value)[:80],
            )
            return await build_and_send_request(session, surface, parameter, payload_value)

        scan_task = asyncio.create_task(
            engine.run_with_attack_modules(
                surfaces=surfaces,
                request_sender=request_sender,
            )
        )

        while not scan_task.done():
            completed = engine.stats.completed
            progress = min(int((completed / total_requests) * 100), 99)
            scans_db[scan_id]["progress"] = progress
            logger.info(
                "[%s] progress=%s%% completed=%s/%s findings=%s failures=%s",
                scan_id,
                progress,
                completed,
                total_requests,
                engine.stats.findings,
                engine.stats.failures,
            )
            await asyncio.sleep(1)

        await scan_task

        findings: list[dict[str, str]] = []
        for finding in engine.findings:
            module_name = finding.module_name or "Unknown"
            lower_name = module_name.lower()
            severity = "High" if ("sql" in lower_name or "brute" in lower_name) else "Medium"
            param_location = getattr(getattr(finding.surface, "param_location", None), "name", "UNKNOWN")
            payload_value = getattr(finding.payload, "value", str(finding.payload))

            findings.append(
                {
                    "severity": severity,
                    "location": str(param_location),
                    "parameter": finding.parameter,
                    "type": module_name,
                    "payload": str(payload_value),
                }
            )

        scans_db[scan_id]["progress"] = 100
        scans_db[scan_id]["status"] = "completed"
        scans_db[scan_id]["findings"] = findings
        scans_db[scan_id]["summary"] = {
            "total_requests": engine.stats.completed,
            "successful_findings": len(findings),
            "failed_requests": engine.stats.failures,
            "elapsed_time": round(time.monotonic() - started_at, 2),
        }
        logger.info("[%s] scan completed findings=%s", scan_id, len(findings))
        for finding in findings:
            logger.warning(
                "[%s] [VULNERABILITY] %s | location=%s | parameter=%s",
                scan_id,
                finding["type"],
                finding["location"],
                finding["parameter"],
            )
    except Exception as exc:
        scans_db[scan_id]["progress"] = 100
        scans_db[scan_id]["status"] = "completed"
        scans_db[scan_id]["error"] = str(exc)
        scans_db[scan_id]["findings"] = []
        scans_db[scan_id]["summary"] = {
            "total_requests": 0,
            "successful_findings": 0,
            "failed_requests": 0,
            "elapsed_time": 0.0,
        }
        logger.exception("[%s] scan failed: %s", scan_id, exc)


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def serve_dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
