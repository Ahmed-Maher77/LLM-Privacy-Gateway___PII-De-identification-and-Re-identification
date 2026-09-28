"""Measure what the README's Concurrency section only asserted: cold start,
steady-state latency, throughput at several worker counts, and peak memory.

Every prior number in this repository was per-document latency inside one
process (``tools/evaluate.py``'s ``latency_s``). Nothing measured what a
deployment actually needs to plan capacity: how long the first request takes
after a cold process start, what the tail (p90/p99) looks like once the model
is warm, how throughput scales across worker processes -- ``analyze()`` is not
thread-safe, so this always measures processes, never threads -- and how much
resident memory one worker actually holds once the model is loaded.

Usage::

    uv run python tools/benchmark.py                       # everything, defaults
    uv run python tools/benchmark.py --cold-start-samples 3
    uv run python tools/benchmark.py --workers 1,2,4,8
    uv run python tools/benchmark.py --report              # write reports/benchmark.json + .md
    uv run python tools/benchmark.py --skip-cold-start      # steady-state + throughput only

Run on the machine, and with the worker count, you intend to deploy with --
these numbers are not portable across hardware.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from multiprocessing import get_context
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures"
DEFAULT_REPORT_JSON = PROJECT_ROOT / "reports" / "benchmark.json"
DEFAULT_REPORT_MD = PROJECT_ROOT / "reports" / "benchmark.md"

# A short document forces the model to load without spending most of the
# sample on inference over a large window.
_COLD_START_TEXT = "Priya Raman: I will send the report to devesh@example.com by Friday."

_COLD_START_MARKER = "--_cold-start-worker"


def _load_corpus_texts(limit: int | None = None) -> list[str]:
    """Real document text, not synthetic filler, for steady-state and throughput."""
    texts = [
        path.read_text(encoding="utf-8")
        for path in sorted(FIXTURE_DIR.glob("*.txt"))
    ]
    if limit is not None:
        texts = texts[:limit]
    if not texts:
        raise SystemExit(f"no fixtures found in {FIXTURE_DIR}")
    return texts


# --------------------------------------------------------------------------
# Cold start
# --------------------------------------------------------------------------


def _cold_start_worker() -> None:
    """Run in a fresh subprocess; prints one JSON line of timings to stdout.

    A model, once loaded, stays loaded for the rest of the process -- the
    only way to measure the *first* call is to pay for a new process every
    time, which is also the honest shape of what a real cold start costs.
    """
    t0 = time.perf_counter()
    import pii  # noqa: F401
    from pii import PIIMiddleware

    t1 = time.perf_counter()
    middleware = PIIMiddleware(on_leak="ignore")
    t2 = time.perf_counter()
    middleware.analyze(_COLD_START_TEXT)
    t3 = time.perf_counter()

    print(
        json.dumps(
            {
                "import_seconds": t1 - t0,
                "construct_seconds": t2 - t1,
                # Bundles model load and first inference -- GLiNER and spaCy
                # both load lazily on first use inside analyze(), not at
                # construction, and there is no supported hook to split the
                # two without reaching into detector internals.
                "first_analyze_seconds": t3 - t2,
                "total_seconds": t3 - t0,
            }
        )
    )


def measure_cold_start(samples: int) -> list[dict]:
    results: list[dict] = []
    for _ in range(samples):
        started = time.perf_counter()
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), _COLD_START_MARKER],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            timeout=300,
        )
        wall_seconds = time.perf_counter() - started
        if proc.returncode != 0:
            raise RuntimeError(f"cold-start subprocess failed:\n{proc.stderr}")
        sample = json.loads(proc.stdout.strip().splitlines()[-1])
        sample["wall_seconds"] = wall_seconds
        results.append(sample)
    return results


# --------------------------------------------------------------------------
# Steady-state latency
# --------------------------------------------------------------------------


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(pct / 100 * (len(ordered) - 1))))
    return ordered[index]


def measure_steady_state(texts: list[str], *, warmup: int, repeats: int) -> dict:
    from pii import PIIMiddleware

    middleware = PIIMiddleware(on_leak="ignore")
    for text in texts[:warmup]:
        middleware.analyze(text)

    latencies: list[float] = []
    by_size: dict[str, list[float]] = {"small": [], "medium": [], "large": []}
    for _ in range(repeats):
        for text in texts:
            started = time.perf_counter()
            middleware.analyze(text)
            elapsed = time.perf_counter() - started
            latencies.append(elapsed)
            bucket = "small" if len(text) < 2000 else "medium" if len(text) < 8000 else "large"
            by_size[bucket].append(elapsed)

    return {
        "documents": len(texts),
        "repeats": repeats,
        "p50_seconds": round(_percentile(latencies, 50), 4),
        "p90_seconds": round(_percentile(latencies, 90), 4),
        "p99_seconds": round(_percentile(latencies, 99), 4),
        "mean_seconds": round(statistics.fmean(latencies), 4) if latencies else 0.0,
        "by_size": {
            bucket: {
                "documents": len(values),
                "p50_seconds": round(_percentile(values, 50), 4) if values else None,
            }
            for bucket, values in by_size.items()
            if values
        },
    }


# --------------------------------------------------------------------------
# Throughput and peak memory, per worker count
# --------------------------------------------------------------------------

_worker_middleware = None  # one per process, built once by _pool_init


def _pool_init(threads_per_worker: int | None = None) -> None:
    """Load the model once per worker process, not once per document.

    This is the deployment shape the README recommends: one ``PIIMiddleware``
    instance per worker, built at process start, never shared across threads.
    Limiting PyTorch intra-op threads per worker process prevents CPU thread
    contention and cache thrashing across concurrent worker processes.
    """
    import os

    if threads_per_worker is not None:
        os.environ["OMP_NUM_THREADS"] = str(threads_per_worker)
        try:
            import torch

            torch.set_num_threads(threads_per_worker)
        except Exception:
            pass

    global _worker_middleware
    from pii import PIIMiddleware

    _worker_middleware = PIIMiddleware(on_leak="ignore")


def _pool_analyze(text: str) -> float:
    started = time.perf_counter()
    _worker_middleware.analyze(text)
    return time.perf_counter() - started


def _pool_rss_bytes(_: int) -> int:
    """``_`` is unused -- ``pool.map`` requires one argument per call."""
    import psutil

    return psutil.Process().memory_info().rss


def _pool_warmup(_: int) -> None:
    """Warm up the worker model so steady-state throughput measures processing capacity."""
    global _worker_middleware
    if _worker_middleware is not None:
        _worker_middleware.analyze("warmup probe: user@example.com", dry_run=True)


def measure_throughput_and_memory(texts: list[str], *, worker_counts: list[int], rounds: int) -> dict:
    """Throughput and RSS at each worker count.

    Workers are warmed up before the timing window begins, ensuring steady-state
    processing capacity and scaling across processes are accurately measured
    without one-time model loading cold-start skew.
    """
    import os

    cpu_count = os.cpu_count() or 1
    ctx = get_context("spawn")
    results: dict[str, dict] = {}
    total_chars = sum(len(t) for t in texts) * rounds
    documents = texts * rounds

    for workers in worker_counts:
        threads = max(1, cpu_count // workers)
        with ctx.Pool(processes=workers, initializer=_pool_init, initargs=(threads,)) as pool:
            pool.map(_pool_warmup, range(workers))
            started = time.perf_counter()
            per_doc = pool.map(_pool_analyze, documents)
            elapsed = time.perf_counter() - started
            # Sampled once, after the batch, while the workers are still
            # alive -- the number that matters for capacity planning is
            # steady-state resident memory with the model loaded, not a
            # transient peak during a single forward pass.
            rss_samples = pool.map(_pool_rss_bytes, range(workers))

        results[str(workers)] = {
            "workers": workers,
            "documents_processed": len(documents),
            "wall_seconds": round(elapsed, 3),
            "documents_per_second": round(len(documents) / elapsed, 2),
            "chars_per_second": round(total_chars / elapsed, 1),
            "mean_latency_seconds": round(statistics.fmean(per_doc), 4),
            "rss_mb_per_worker": [round(b / (1024 * 1024), 1) for b in rss_samples],
            "rss_mb_max": round(max(rss_samples) / (1024 * 1024), 1),
        }
    return results


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def build_markdown(report: dict) -> str:
    lines = ["# Benchmark", ""]
    if "cold_start" in report:
        cs = report["cold_start"]
        lines += [
            "## Cold start",
            "",
            f"Samples: {len(cs)}",
            "",
            "| sample | import s | construct s | first analyze s | total s |",
            "|---|---|---|---|---|",
        ]
        for i, s in enumerate(cs):
            lines.append(
                f"| {i} | {s['import_seconds']:.3f} | {s['construct_seconds']:.3f} "
                f"| {s['first_analyze_seconds']:.3f} | {s['total_seconds']:.3f} |"
            )
        lines.append("")

    if "steady_state" in report:
        ss = report["steady_state"]
        lines += [
            "## Steady-state latency",
            "",
            f"- Documents: {ss['documents']} x {ss['repeats']} repeat(s)",
            f"- p50: `{ss['p50_seconds']}s`  p90: `{ss['p90_seconds']}s`  p99: `{ss['p99_seconds']}s`  mean: `{ss['mean_seconds']}s`",
            "",
        ]
        for bucket, row in ss.get("by_size", {}).items():
            lines.append(f"  - {bucket}: {row['documents']} doc(s), p50 `{row['p50_seconds']}s`")
        lines.append("")

    if "throughput" in report:
        lines += [
            "## Throughput and memory by worker count",
            "",
            "| workers | docs/s | chars/s | mean latency s | RSS/worker MB (max) |",
            "|---|---|---|---|---|",
        ]
        for row in report["throughput"].values():
            lines.append(
                f"| {row['workers']} | {row['documents_per_second']} | {row['chars_per_second']} "
                f"| {row['mean_latency_seconds']} | {row['rss_mb_max']} |"
            )
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(_COLD_START_MARKER, action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--cold-start-samples", type=int, default=3)
    parser.add_argument("--skip-cold-start", action="store_true")
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--repeats", type=int, default=2, help="passes over the corpus for steady-state")
    parser.add_argument("--workers", default="1,2,4", help="comma-separated worker counts")
    parser.add_argument("--rounds", type=int, default=1, help="corpus repetitions per worker count")
    parser.add_argument("--limit", type=int, default=None, help="use only the first N fixtures (for a quick run)")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--report-json", default=str(DEFAULT_REPORT_JSON))
    parser.add_argument("--report-md", default=str(DEFAULT_REPORT_MD))
    args = parser.parse_args()

    # Re-entry point for the cold-start subprocess -- see measure_cold_start().
    if args._cold_start_worker:
        _cold_start_worker()
        return 0

    texts = _load_corpus_texts(limit=args.limit)
    report: dict = {}

    if not args.skip_cold_start:
        print(f"Cold start: {args.cold_start_samples} fresh subprocess(es)...")
        report["cold_start"] = measure_cold_start(args.cold_start_samples)
        for s in report["cold_start"]:
            print(f"  total {s['total_seconds']:.3f}s  (import {s['import_seconds']:.3f}s, "
                  f"construct {s['construct_seconds']:.3f}s, first analyze {s['first_analyze_seconds']:.3f}s)")

    print(f"\nSteady-state: {len(texts)} document(s) x {args.repeats} repeat(s), warmup {args.warmup}...")
    report["steady_state"] = measure_steady_state(texts, warmup=args.warmup, repeats=args.repeats)
    ss = report["steady_state"]
    print(f"  p50={ss['p50_seconds']}s p90={ss['p90_seconds']}s p99={ss['p99_seconds']}s mean={ss['mean_seconds']}s")

    worker_counts = [int(w) for w in args.workers.split(",") if w.strip()]
    print(f"\nThroughput and memory at worker counts {worker_counts}...")
    report["throughput"] = measure_throughput_and_memory(texts, worker_counts=worker_counts, rounds=args.rounds)
    for row in report["throughput"].values():
        print(
            f"  workers={row['workers']:<3} {row['documents_per_second']:.2f} docs/s  "
            f"RSS/worker up to {row['rss_mb_max']} MB"
        )

    if args.report:
        report_json = Path(args.report_json)
        report_md = Path(args.report_md)
        report_json.parent.mkdir(parents=True, exist_ok=True)
        report_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        report_md.write_text(build_markdown(report), encoding="utf-8")
        print(f"\nWritten to {report_json} and {report_md}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
