"""High-resolution stage timing.

Uses ``time.perf_counter``. The report keeps the prototype's four top-level
keys so existing consumers do not break, and adds the full per-stage breakdown
alongside them.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass(slots=True)
class Timings:
    stages: dict[str, float] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)
    _started: float = field(default_factory=time.perf_counter)

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        started = time.perf_counter()
        try:
            yield
        finally:
            self.record(name, time.perf_counter() - started)

    def record(self, name: str, seconds: float) -> None:
        self.stages[name] = self.stages.get(name, 0.0) + seconds

    def count(self, name: str, value: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + value

    @property
    def total(self) -> float:
        return time.perf_counter() - self._started

    def detector_seconds(self) -> dict[str, float]:
        return {
            name.removeprefix("detect."): seconds
            for name, seconds in self.stages.items()
            if name.startswith("detect.")
        }

    def to_dict(self) -> dict[str, object]:
        detection = sum(
            seconds
            for name, seconds in self.stages.items()
            if name.startswith("detect.")
            or name in {"normalize", "parse_transcript", "build_registry",
                        "aggregate", "policy", "injection_guard"}
        )
        llm = self.stages.get("llm.invoke", 0.0) + self.stages.get("llm.retry", 0.0)
        restoration = self.stages.get("scan.output", 0.0)
        total = self.total
        return {
            # Prototype-compatible keys.
            "anonymization_seconds": round(detection + self.stages.get("pseudonymize", 0.0), 6),
            "llm_seconds": round(llm, 6),
            "restoration_seconds": round(restoration, 6),
            "total_seconds": round(total, 6),
            # The honest breakdown.
            "overhead_seconds": round(total - llm, 6),
            "overhead_fraction": round((total - llm) / total, 6) if total > 0 else None,
            "stages": {k: round(v, 6) for k, v in sorted(self.stages.items())},
            "detector_seconds": {k: round(v, 6) for k, v in sorted(self.detector_seconds().items())},
            "counters": dict(sorted(self.counters.items())),
        }

