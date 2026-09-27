"""Latency and memory benchmark.

``--mode overhead`` is the default and makes **no network call at all**. That is
deliberate: the overhead is the number the gateway is responsible for, the
downstream model is a hosted service whose latency the gateway does not control,
and a benchmark that cannot run without it is a benchmark that mostly does not
run.

``--mode e2e`` adds the model and is honest about what it cannot separate: the
baseline and protected arms send *different prompts* and receive
*different-length completions*, and completion length dominates latency. The
difference in model time between the arms is therefore not attributable to the
gateway. The gateway's cost is the overhead.

Percentiles are suppressed at the data layer when the sample cannot support
them. A p99 from 30 samples is the maximum wearing a percentile's name, and a
caveat in prose does not survive being pasted into a slide.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO / "benchmarks" / "results"

#: Minimum sample size for each percentile to be emitted at all.
PERCENTILE_FLOORS = {"p50": 5, "p95": 20, "p99": 100}


def percentiles(values: Sequence[float]) -> tuple[dict[str, float], dict[str, str]]:
    """Return the percentiles the sample supports, and why the others are absent."""
    reported: dict[str, float] = {}
    withheld: dict[str, str] = {}
    ordered = sorted(values)
    n = len(ordered)
    for name, floor in PERCENTILE_FLOORS.items():
        if n < floor:
            withheld[name] = f"n={n} < {floor} required"
            continue
        q = int(name[1:]) / 100.0
        rank = max(1, min(n, round(q * n + 0.5)))
        reported[name] = ordered[rank - 1]
    return reported, withheld


def summarise(values: Sequence[float]) -> dict[str, object]:
    if not values:
        return {"n": 0, "note": "not measured"}
    reported, withheld = percentiles(values)
    out: dict[str, object] = {
        "n": len(values),
        "min": round(min(values), 6),
        "median": round(statistics.median(values), 6),
        "mean": round(statistics.fmean(values), 6),
        "max": round(max(values), 6),
    }
    if len(values) > 1:
        out["stdev"] = round(statistics.stdev(values), 6)
        ordered = sorted(values)
        q1 = ordered[len(ordered) // 4]
        q3 = ordered[(3 * len(ordered)) // 4]
        out["iqr"] = round(q3 - q1, 6)
    out.update({k: round(v, 6) for k, v in reported.items()})
    if withheld:
        out["percentiles_withheld"] = withheld
    return out


def _git(*args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", *args], capture_output=True, text=True, timeout=5, check=False
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def machine_info() -> dict[str, object]:
    import os

    info: dict[str, object] = {
        # Hashed, not raw: enough to tell two machines apart without publishing
        # a corporate hostname.
        "hostname_sha256_8": sha256(platform.node().encode()).hexdigest()[:8],
        "os": platform.platform(),
        "cpu": platform.processor() or platform.machine(),
        "cpu_count_logical": os.cpu_count(),
        "python": platform.python_version(),
    }
    try:
        import psutil

        info["ram_total_gb"] = round(psutil.virtual_memory().total / 1024**3, 1)
    except ImportError:
        info["ram_total_gb"] = None
    try:
        import torch

        info["torch"] = torch.__version__
        info["torch_num_threads"] = torch.get_num_threads()
        info["cuda_available"] = torch.cuda.is_available()
    except ImportError:
        info["torch"] = None
    return info


def rss_mb() -> float | None:
    try:
        import psutil

        return psutil.Process().memory_info().rss / 1024**2
    except ImportError:
        return None


def run_overhead(
    documents: list[tuple[str, str]], detectors: tuple[str, ...], warmup: int, runs: int
) -> dict[str, object]:
    from privacy_gateway.config import DetectorSettings, Settings
    from privacy_gateway.gateway import GatewayRequest, PrivacyGateway
    from privacy_gateway.llm.mock_client import EchoLLMClient

    settings = Settings(
        detectors=DetectorSettings(enabled=detectors, required=("regex", "registry"))
    )
    baseline_rss = rss_mb()
    gateway = PrivacyGateway(settings, llm=EchoLLMClient())

    # Warm the models before measuring, and record the cost separately.
    warm_started = time.perf_counter()
    for _ in range(max(1, warmup)):
        for _, text in documents:
            gateway.sanitize(GatewayRequest(text=text, conversation_id="c-warmup"))
    warmup_seconds = time.perf_counter() - warm_started
    warm_rss = rss_mb()

    per_document: dict[str, dict[str, object]] = {}
    for name, text in documents:
        totals: list[float] = []
        stages: dict[str, list[float]] = {}
        chars = 0
        entities = 0
        for index in range(runs):
            started = time.perf_counter()
            outcome = gateway.sanitize(GatewayRequest(text=text, conversation_id=f"c-{index}"))
            totals.append(time.perf_counter() - started)
            chars = len(outcome.normalized.text)
            entities = len(outcome.entities)
        per_document[name] = {
            "chars": chars,
            "entities": entities,
            "seconds": summarise(totals),
            "ms_per_1000_chars": round(1000 * statistics.median(totals) / (chars / 1000), 4)
            if chars
            else None,
        }
        _ = stages

    end_rss = rss_mb()
    return {
        "documents": per_document,
        "warmup": {"runs": warmup, "seconds": round(warmup_seconds, 4)},
        "memory_mb": {
            "baseline": round(baseline_rss, 1) if baseline_rss else None,
            "after_warmup": round(warm_rss, 1) if warm_rss else None,
            "model_footprint": round(warm_rss - baseline_rss, 1)
            if warm_rss and baseline_rss
            else None,
            "after_runs": round(end_rss, 1) if end_rss else None,
            "growth_during_runs": round(end_rss - warm_rss, 1)
            if end_rss and warm_rss
            else None,
        },
    }


def run_e2e(
    documents: list[tuple[str, str]], detectors: tuple[str, ...], runs: int
) -> dict[str, object]:
    from privacy_gateway.config import DetectorSettings, Settings
    from privacy_gateway.errors import GatewayError
    from privacy_gateway.gateway import GatewayRequest, PrivacyGateway
    from privacy_gateway.llm.base import build_llm
    from privacy_gateway.llm.prompt import PromptWrapper

    settings = Settings(
        detectors=DetectorSettings(enabled=detectors, required=("regex", "registry"))
    )
    llm = build_llm(settings.llm)
    if not llm.health():
        return {"status": "skipped", "reason": "model unreachable", "metrics": None}

    gateway = PrivacyGateway(settings, llm=llm)
    wrapper = PromptWrapper()
    out: dict[str, object] = {}

    for name, text in documents:
        baseline: list[float] = []
        protected_total: list[float] = []
        protected_overhead: list[float] = []
        protected_llm: list[float] = []
        errors = 0
        # Interleaved, so drift in the hosted service hits both arms equally.
        for index in range(runs):
            try:
                prompt = wrapper.wrap(text)
                started = time.perf_counter()
                llm.invoke(prompt.user, system=prompt.system or None)
                baseline.append(time.perf_counter() - started)
            except (GatewayError, Exception):
                errors += 1
            try:
                started = time.perf_counter()
                result = gateway.run(
                    GatewayRequest(text=text, conversation_id=f"c-bench-{index}")
                )
                total = time.perf_counter() - started
                llm_seconds = result.timings.stages.get("llm.invoke", 0.0)
                protected_total.append(total)
                protected_llm.append(llm_seconds)
                protected_overhead.append(total - llm_seconds)
            except (GatewayError, Exception):
                errors += 1

        out[name] = {
            "baseline_llm_seconds": summarise(baseline),
            "protected_total_seconds": summarise(protected_total),
            "protected_llm_seconds": summarise(protected_llm),
            "protected_overhead_seconds": summarise(protected_overhead),
            "overhead_fraction_median": (
                round(statistics.median(protected_overhead) / statistics.median(protected_total), 4)
                if protected_overhead and protected_total
                else None
            ),
            "llm_errors": errors,
        }
    return {"status": "ok", "metrics": out}


CONFOUND_NOTE = (
    "The baseline and protected arms send different prompts and receive "
    "different-length completions, and completion length dominates model "
    "latency. The difference in model time between the arms is therefore NOT "
    "attributable to the gateway. The gateway's cost is "
    "protected_overhead_seconds."
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("overhead", "e2e"), default="overhead")
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument(
        "--detectors", default="regex,registry,domain,presidio,ner",
        help="comma-separated detector names",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    detectors = tuple(d.strip() for d in args.detectors.split(",") if d.strip())
    documents = [
        (path.name, path.read_bytes().decode("utf-8"))
        for path in sorted((REPO / "test_data").glob("*.txt"))
        if "sanitized" not in path.name
    ]

    from privacy_gateway.config import Settings

    settings = Settings.from_env()
    payload: dict[str, object] = {
        "provenance": {
            "schema_version": 1,
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "generated_by": f"benchmarks/bench.py --mode {args.mode} --runs {args.runs}",
            "git_commit": _git("rev-parse", "--short", "HEAD"),
            "git_dirty": bool(_git("status", "--porcelain")),
            "machine": machine_info(),
            "mode": args.mode,
            "llm_invoked": args.mode == "e2e",
            "llm_model": settings.llm.model if args.mode == "e2e" else None,
            "qwen_enabled": settings.qwen.enabled,
            "qwen_skip_reason": (
                None if settings.qwen.enabled else "disabled by default; no model pulled"
            ),
            "detectors": list(detectors),
            "runs": {"warmup": args.warmup, "measured": args.runs},
            "percentile_floors": PERCENTILE_FLOORS,
            "input_files": [
                {"name": name, "chars": len(text), "sha256": sha256(text.encode()).hexdigest()[:16]}
                for name, text in documents
            ],
        }
    }

    if args.mode == "overhead":
        payload["overhead"] = run_overhead(documents, detectors, args.warmup, args.runs)
        payload["e2e"] = {"status": "not_run", "reason": "mode=overhead", "metrics": None}
    else:
        payload["e2e"] = run_e2e(documents, detectors, args.runs)
        payload["e2e_confound_note"] = CONFOUND_NOTE

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    host = payload["provenance"]["machine"]["hostname_sha256_8"]  # type: ignore[index]
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{stamp}_{host}_{args.mode}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=True))
    print(f"\nWritten to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
