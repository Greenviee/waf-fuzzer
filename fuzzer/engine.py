from __future__ import annotations

import asyncio
from dataclasses import dataclass
from inspect import isawaitable
from typing import Any, Awaitable, Callable, Iterable, Protocol

import aiohttp

try:
    from core.models import AttackSurface  # type: ignore
except (ImportError, AttributeError):
    # Temporary fallback for bootstrap phase where models are incomplete.
    @dataclass(slots=True)
    class AttackSurface:  # type: ignore[no-redef]
        url: str
        method: str = "GET"
        parameters: dict[str, Any] | list[str] | None = None
        headers: dict[str, str] | None = None
        body: dict[str, Any] | str | None = None


@dataclass(slots=True, frozen=True)
class AttackJob:
    surface: AttackSurface
    parameter: str
    payload: str


@dataclass(slots=True)
class Finding:
    surface: AttackSurface
    parameter: str
    payload: str
    response: Any


@dataclass(slots=True)
class EngineStats:
    queued: int = 0
    completed: int = 0
    failures: int = 0
    findings: int = 0


class AsyncRequestSender(Protocol):
    async def __call__(
        self,
        session: aiohttp.ClientSession,
        surface: AttackSurface,
        parameter: str,
        payload: str,
    ) -> Any: ...


VulnerabilityChecker = Callable[[Any], bool | Awaitable[bool]]
ResultCallback = Callable[[Finding], None | Awaitable[None]]


class FuzzerEngine:
    def __init__(
        self,
        *,
        max_concurrent_requests: int = 20,
        worker_count: int = 10,
        delay: float = 0.0,
        request_timeout: float = 15.0,
        queue_maxsize: int = 0,
    ) -> None:
        if max_concurrent_requests < 1:
            raise ValueError("max_concurrent_requests must be >= 1")
        if worker_count < 1:
            raise ValueError("worker_count must be >= 1")
        if delay < 0:
            raise ValueError("delay must be >= 0")

        self.max_concurrent_requests = max_concurrent_requests
        self.worker_count = worker_count
        self.delay = delay
        self.request_timeout = request_timeout

        self._semaphore = asyncio.Semaphore(max_concurrent_requests)
        self._queue: asyncio.Queue[AttackJob | None] = asyncio.Queue(maxsize=queue_maxsize)
        self._stats = EngineStats()
        self._stats_lock = asyncio.Lock()
        self._findings: list[Finding] = []

    @property
    def stats(self) -> EngineStats:
        return EngineStats(
            queued=self._stats.queued,
            completed=self._stats.completed,
            failures=self._stats.failures,
            findings=self._stats.findings,
        )

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    async def run(
        self,
        *,
        surfaces: Iterable[AttackSurface],
        payloads: Iterable[str],
        request_sender: AsyncRequestSender,
        is_vulnerable: VulnerabilityChecker,
        on_finding: ResultCallback | None = None,
    ) -> EngineStats:
        payload_list = list(payloads)
        if not payload_list:
            raise ValueError("payloads must not be empty")

        timeout = aiohttp.ClientTimeout(total=self.request_timeout)
        connector = aiohttp.TCPConnector(limit=self.max_concurrent_requests * 2)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            workers = [
                asyncio.create_task(
                    self._worker(
                        worker_id=index + 1,
                        session=session,
                        request_sender=request_sender,
                        is_vulnerable=is_vulnerable,
                        on_finding=on_finding,
                    )
                )
                for index in range(self.worker_count)
            ]

            await self._enqueue_jobs(surfaces=surfaces, payloads=payload_list)
            await self._queue.join()

            for _ in workers:
                await self._queue.put(None)
            await asyncio.gather(*workers, return_exceptions=False)

        return self.stats

    async def _enqueue_jobs(
        self,
        *,
        surfaces: Iterable[AttackSurface],
        payloads: list[str],
    ) -> None:
        for surface in surfaces:
            for parameter in self._iter_parameters(surface):
                for payload in payloads:
                    await self._queue.put(
                        AttackJob(surface=surface, parameter=parameter, payload=payload)
                    )
                    async with self._stats_lock:
                        self._stats.queued += 1

    async def _worker(
        self,
        *,
        worker_id: int,
        session: aiohttp.ClientSession,
        request_sender: AsyncRequestSender,
        is_vulnerable: VulnerabilityChecker,
        on_finding: ResultCallback | None,
    ) -> None:
        while True:
            job = await self._queue.get()
            if job is None:
                self._queue.task_done()
                return

            try:
                await self._process_job(
                    session=session,
                    job=job,
                    request_sender=request_sender,
                    is_vulnerable=is_vulnerable,
                    on_finding=on_finding,
                )
            except Exception as exc:
                async with self._stats_lock:
                    self._stats.failures += 1
                print(f"[worker:{worker_id}] request failed: {exc}")
            finally:
                async with self._stats_lock:
                    self._stats.completed += 1
                self._queue.task_done()

    async def _process_job(
        self,
        *,
        session: aiohttp.ClientSession,
        job: AttackJob,
        request_sender: AsyncRequestSender,
        is_vulnerable: VulnerabilityChecker,
        on_finding: ResultCallback | None,
    ) -> None:
        async with self._semaphore:
            response = await request_sender(
                session=session,
                surface=job.surface,
                parameter=job.parameter,
                payload=job.payload,
            )

            if self.delay > 0:
                await asyncio.sleep(self.delay)

        verdict = is_vulnerable(response)
        is_hit = await verdict if isawaitable(verdict) else verdict
        if not is_hit:
            return

        finding = Finding(
            surface=job.surface,
            parameter=job.parameter,
            payload=job.payload,
            response=response,
        )
        self._findings.append(finding)
        async with self._stats_lock:
            self._stats.findings += 1

        if on_finding is not None:
            callback_result = on_finding(finding)
            if isawaitable(callback_result):
                await callback_result

    @staticmethod
    def _iter_parameters(surface: AttackSurface) -> Iterable[str]:
        params = getattr(surface, "parameters", None)
        if params is None:
            return ()
        if isinstance(params, dict):
            return params.keys()
        return tuple(str(p) for p in params)
