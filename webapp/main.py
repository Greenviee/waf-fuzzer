from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

SCAN_TYPES = ["all", "sqli", "bruteforce", "lfi", "file_upload", "ssrf"]


class AuthSettings(BaseModel):
    login_url: str = ""
    cookie: str = ""
    username: str = ""
    password: str = ""
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: str = "user_token"
    submit_field: str = "Login"


class EngineOptions(BaseModel):
    rps: int = Field(default=50, ge=1, le=10000)
    session_pool_size: int = Field(default=3, ge=1, le=100)
    output: str = "scan_report.json"
    surfaces_output: str = "attack_surfaces.json"


class SQLiOptions(BaseModel):
    sqli_evasion_level: int = Field(default=1, ge=0, le=3)
    include_time_based: bool = False
    max_time_payloads: int = Field(default=0, ge=0)


class BruteforceOptions(BaseModel):
    bf_wordlist: str = "config/payloads/common_passwords.txt"
    bf_disable_mutation: bool = False
    bf_mutation_level: int = Field(default=1, ge=0, le=3)
    bf_true_random: bool = False
    bf_charset: str = "abcdefghijklmnopqrstuvwxyz0123456789"
    bf_min_length: int = Field(default=1, ge=1)
    bf_max_length: int = Field(default=3, ge=1)
    bf_length: str = ""
    bf_max_dictionary: int = Field(default=0, ge=0)
    bf_max_true_random: int = Field(default=0, ge=0)
    bf_stop_on_first_hit: bool = True
    bf_request_file: str = ""
    bf_target_url: str = ""
    bf_method: Literal["GET", "POST"] = "GET"
    bf_fuzz_param: str = "password"
    bf_target_param: str = ""
    bf_username_param: str = "username"
    bf_username: str = "admin"
    bf_extra_params: list[str] = Field(default_factory=list)


class LFIOptions(BaseModel):
    lfi_evasion_level: int = Field(default=1, ge=0, le=3)


class SSRFOptions(BaseModel):
    ssrf_bypass_level: int = Field(default=1, ge=0, le=2)
    ssrf_include_oob: bool = False


class ScanRequest(BaseModel):
    target_url: str = Field(..., min_length=1, max_length=2048, alias="url")
    scan_type: Literal["all", "sqli", "bruteforce", "lfi", "file_upload", "ssrf"] = "all"
    auth: AuthSettings = Field(default_factory=AuthSettings)
    engine: EngineOptions = Field(default_factory=EngineOptions)
    sqli: SQLiOptions = Field(default_factory=SQLiOptions)
    bruteforce: BruteforceOptions = Field(default_factory=BruteforceOptions)
    lfi: LFIOptions = Field(default_factory=LFIOptions)
    ssrf: SSRFOptions = Field(default_factory=SSRFOptions)

    model_config = {"populate_by_name": True}


app = FastAPI(
    title="WAF Fuzzer Web UI Mock API",
    description="Mock backend that matches current CLI options and modules.",
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

scans_db: dict[str, dict] = {}


@app.get("/api/schema")
async def get_schema() -> dict:
    return {
        "scan_types": SCAN_TYPES,
        "defaults": {
            "rps": 50,
            "session_pool_size": 3,
            "sqli_evasion_level": 1,
            "lfi_evasion_level": 1,
            "ssrf_bypass_level": 1,
            "bf_mutation_level": 1,
            "bf_method": "GET",
        },
    }


@app.post("/api/scan/start")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks) -> dict:
    scan_id = str(uuid4())
    now = time.time()
    scans_db[scan_id] = {
        "scan_id": scan_id,
        "status": "queued",
        "progress": 0,
        "created_at": now,
        "updated_at": now,
        "request": req.model_dump(by_alias=True),
        "result": None,
    }
    background_tasks.add_task(_simulate_scan, scan_id)
    return {
        "status": "accepted",
        "message": "Mock scan registered in queue.",
        "scan_id": scan_id,
        "request": req.model_dump(by_alias=True),
    }


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    scan = scans_db.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return scan


async def _simulate_scan(scan_id: str) -> None:
    steps = [5, 15, 35, 55, 75, 90, 100]
    for idx, progress in enumerate(steps):
        await asyncio.sleep(0.5 if idx == 0 else 1.0)
        scan = scans_db.get(scan_id)
        if scan is None:
            return
        scan["status"] = "running" if progress < 100 else "completed"
        scan["progress"] = progress
        scan["updated_at"] = time.time()
        if progress == 100:
            req = scan.get("request", {})
            scan["result"] = {
                "summary": {
                    "target": req.get("url", ""),
                    "scan_type": req.get("scan_type", "all"),
                    "total_requests": 0,
                    "findings": 0,
                },
                "note": "Mock result only. Connect here to cli/runner.py for real execution.",
            }


@app.get("/")
async def serve_index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
