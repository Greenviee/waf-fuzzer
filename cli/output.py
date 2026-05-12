from __future__ import annotations

import asyncio

from fuzzer import FuzzerEngine


async def progress_printer(
    engine: FuzzerEngine,
    total_requests: int,
    scan_task: asyncio.Task,
) -> None:
    total = max(total_requests, 1)
    while not scan_task.done():
        completed = min(engine.stats.completed, total)
        percent = (completed / total) * 100
        print(f"\rProgress: {percent:6.2f}% ({completed}/{total})", end="", flush=True)
        await asyncio.sleep(0.2)

    completed = min(engine.stats.completed, total)
    percent = (completed / total) * 100
    print(f"\rProgress: {percent:6.2f}% ({completed}/{total})", end="", flush=True)
    print()


def print_scan_configuration(
    *,
    base_url: str,
    surface_count: int,
    attack_type: str,
    module_count: int,
    payload_count: int,
    sqli_time_based: bool,
    sqli_time_max: int,
    total_requests: int,
    rps: int,
    delay: float,
    queue_workers: int,
    session_pool_size: int,
) -> None:
    print("=" * 60)
    print(f"Target URL:     {base_url}")
    print(f"Surface count:  {surface_count}")
    print(f"Attack type:    {attack_type}")
    print(f"Module count:   {module_count}")
    print(f"Payload count:  {payload_count}")
    print(
        "SQLi timing:    "
        + ("included" if sqli_time_based else "excluded (fast mode)")
        + (f", max={sqli_time_max}" if sqli_time_based else "")
    )
    print(f"Total requests: {total_requests}")
    print("Evasions:       off (mutator disabled)")
    print(f"Throttle (rps): {rps} (delay {delay:.3f}s)")
    print(f"Queue workers:  {queue_workers}")
    print(f"Session pool:   {session_pool_size}")
    print("=" * 60 + "\n")

