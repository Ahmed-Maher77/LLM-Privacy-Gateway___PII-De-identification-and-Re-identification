"""Acceptance test harness over test_data/ transcripts.

Runs the PII pipeline over every transcript in test_data/ (with LLM skipped),
recording per-document status, entity counts, leak counts, residual counts,
latency, and word-diff replacements.

Usage:
    uv run python tools/acceptance.py                   # Run and print summary
    uv run python tools/acceptance.py --write-baseline  # Write tests/acceptance_baseline.json
    uv run python tools/acceptance.py --check           # Assert no regressions vs baseline
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
import time
import warnings
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pii import PIIMiddleware
from pii.policy import DEFAULT_PROFILE

DEFAULT_DIR = PROJECT_ROOT / "test_data"
DEFAULT_BASELINE = PROJECT_ROOT / "tests" / "acceptance_baseline.json"
PLACEHOLDER_RE = re.compile(r"\{\{([A-Z][A-Z0-9_]*_\d+)\}\}")


def extract_diff_pairs(original: str, sanitized: str) -> list[dict[str, str]]:
    """Recover (surface -> placeholder) pairs by diffing original vs sanitized text."""
    orig_words = original.split()
    san_words = sanitized.split()
    matcher = difflib.SequenceMatcher(None, orig_words, san_words)
    pairs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "delete"):
            orig_text = " ".join(orig_words[i1:i2])
            san_text = " ".join(san_words[j1:j2]) if tag == "replace" else ""
            placeholders = PLACEHOLDER_RE.findall(san_text)
            for ph in placeholders:
                token = f"{{{{{ph}}}}}"
                key = (orig_text, token)
                if key not in seen:
                    seen.add(key)
                    pairs.append({"surface": orig_text, "placeholder": token})

    return sorted(pairs, key=lambda p: (p["placeholder"], p["surface"]))


def run_acceptance(
    directory: Path = DEFAULT_DIR,
    profile: str = DEFAULT_PROFILE,
) -> dict:
    """Run pipeline over all .txt files in directory."""
    files = sorted(directory.glob("*.txt"))
    if not files:
        raise SystemExit(f"No .txt files found in {directory}")

    middleware = PIIMiddleware(profile=profile, on_leak="warn")
    results = {}
    total_clean = 0
    total_failed = 0

    print(f"Running acceptance evaluation on {len(files)} documents in {directory.name}...")
    for f in files:
        text = f.read_text(encoding="utf-8")
        start = time.perf_counter()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            analysis = middleware.analyze(text)
        elapsed = round(time.perf_counter() - start, 3)

        entity_counts = dict(Counter(s.label for s in analysis.spans))
        high_leaks = [
            l.get("value", "") for l in analysis.leaks if l.get("severity") == "high"
        ]
        medium_leaks = [
            l.get("value", "") for l in analysis.leaks if l.get("severity") == "medium"
        ]

        high_residual: dict[str, int] = Counter()
        medium_residual: dict[str, int] = Counter()
        for finding in analysis.residual:
            if finding.suppressed_by:
                continue
            if finding.severity == "high":
                high_residual[finding.rule] += 1
            elif finding.severity == "medium":
                medium_residual[finding.rule] += 1

        diff_pairs = extract_diff_pairs(text, analysis.sanitized)

        if analysis.status == "clean":
            total_clean += 1
        elif analysis.status == "failed":
            total_failed += 1

        results[f.name] = {
            "status": analysis.status,
            "bytes": len(text),
            "seconds": elapsed,
            "entity_counts": entity_counts,
            "total_entities": len(analysis.spans),
            "high_leaks_count": len(high_leaks),
            "high_leaks": high_leaks,
            "medium_leaks_count": len(medium_leaks),
            "high_residual": dict(high_residual),
            "medium_residual": dict(medium_residual),
            "replacements": diff_pairs,
        }

        print(
            f"  {f.name:<45} {analysis.status:<7} {len(analysis.spans):>3} ents  "
            f"high_leaks={len(high_leaks)} high_res={sum(high_residual.values())} ({elapsed}s)"
        )

    summary = {
        "documents": len(files),
        "clean": total_clean,
        "failed": total_failed,
        "results": results,
    }
    print(f"\nTotal: {len(files)} documents (clean: {total_clean}, failed: {total_failed})")
    return summary


def check_against_baseline(summary: dict, baseline_path: Path = DEFAULT_BASELINE) -> int:
    """Compare summary against baseline and exit non-zero on regression."""
    if not baseline_path.is_file():
        print(f"Baseline file {baseline_path} not found.", file=sys.stderr)
        return 1

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    base_results = baseline.get("results", {})
    curr_results = summary.get("results", {})

    regressions = []
    for name, base in base_results.items():
        if name not in curr_results:
            regressions.append(f"{name}: missing from current evaluation")
            continue

        curr = curr_results[name]
        # Check 1: clean -> failed
        if base["status"] == "clean" and curr["status"] != "clean":
            regressions.append(
                f"{name}: regressed status from clean to {curr['status']}"
            )

        # Check 2: new high-severity leaks or findings
        if curr["high_leaks_count"] > base["high_leaks_count"]:
            regressions.append(
                f"{name}: high leaks increased from {base['high_leaks_count']} to {curr['high_leaks_count']}"
            )

        curr_high_res = sum(curr.get("high_residual", {}).values())
        base_high_res = sum(base.get("high_residual", {}).values())
        if curr_high_res > base_high_res:
            regressions.append(
                f"{name}: high residual findings increased from {base_high_res} to {curr_high_res}"
            )

        # Check 3: total entity count moving by more than +-10% (when base > 0)
        base_ents = base.get("total_entities", 0)
        curr_ents = curr.get("total_entities", 0)
        if base_ents > 10:
            pct_change = abs(curr_ents - base_ents) / base_ents
            if pct_change > 0.10:
                print(
                    f"  [info] {name}: entity count shifted from {base_ents} to {curr_ents} ({pct_change:.1%})"
                )

    if regressions:
        print("\nREGRESSIONS DETECTED:", file=sys.stderr)
        for r in regressions:
            print(f"  ! {r}", file=sys.stderr)
        return 1

    print("\nAcceptance check PASSED: No regressions vs baseline.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR, help="Transcripts directory")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE, help="Path to baseline JSON")
    parser.add_argument("--write-baseline", action="store_true", help="Record current results as baseline")
    parser.add_argument("--check", action="store_true", help="Assert no regressions against baseline")
    parser.add_argument("--json-out", type=Path, default=None, help="Save summary to JSON file")
    args = parser.parse_args()

    summary = run_acceptance(args.dir)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Saved summary to {args.json_out}")

    if args.write_baseline:
        args.baseline.parent.mkdir(parents=True, exist_ok=True)
        args.baseline.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Wrote baseline to {args.baseline}")
        return 0

    if args.check:
        return check_against_baseline(summary, args.baseline)

    return 0


if __name__ == "__main__":
    sys.exit(main())
