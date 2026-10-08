"""Shared timing and output for the Python adapters.

Contract (same for every adapter): `<adapter> INPUT OUTPUT RUNS`. The first
call is timed from process start, so it includes imports and model loading;
the remaining RUNS calls are timed individually. OUTPUT receives JSON with the
sanitized text of the first call.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from pathlib import Path

STARTED = time.perf_counter()


def run(name: str, redact: Callable[[str], str]) -> None:
    source, target, runs = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
    text = source.read_text(encoding="utf-8")

    sanitized = redact(text)
    cold = time.perf_counter() - STARTED

    warm = []
    for _ in range(runs):
        t0 = time.perf_counter()
        redact(text)
        warm.append(time.perf_counter() - t0)

    try:
        import psutil

        rss_mb = psutil.Process().memory_info().rss / 2**20
    except ImportError:
        rss_mb = None

    target.write_text(
        json.dumps({"name": name, "sanitized": sanitized, "cold_s": cold, "warm_s": warm, "rss_mb": rss_mb}),
        encoding="utf-8",
    )
