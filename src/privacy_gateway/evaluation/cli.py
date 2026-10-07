"""Evaluation CLI.

    uv run python -m privacy_gateway.evaluation.cli sweep --configs A,B,D,E

Writes ``metrics.json`` plus a markdown table rendered from it, and per-config
error files with surrounding context so the errors can actually be triaged.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from ..config import Settings
from ..report import provenance
from .gold import GoldSet
from .metrics import evaluate, without_speaker_lines
from .report import render_markdown
from .sweep import dataset_summary, populate_cache, run_sweep, select

REPO = Path(__file__).resolve().parents[3]
DEFAULT_GOLD = REPO / "evaluation" / "gold"
DEFAULT_OUT = REPO / "evaluation" / "results"


def cmd_sweep(args: argparse.Namespace) -> int:
    gold = GoldSet.load(args.gold)
    # Unlabelled sampling artifacts sit in the same directory; skip them.
    gold = GoldSet(tuple(d for d in gold if d.labeler), gold.path)
    gold = gold.for_split(args.split)
    if not len(gold):
        print("no labelled documents found")
        return 2

    problems = gold.validate()
    if problems:
        for problem in problems[:20]:
            print(f"  INVALID: {problem}")
        return 2

    settings = Settings.from_env()
    configs = select(args.configs)
    cache = populate_cache(gold, sorted({n for c in configs for n in c.detectors}), settings)
    results, cache = run_sweep(gold, configs, settings, cache)

    # The same sweep with speaker-label lines removed from both sides.
    from ..aggregation.aggregator import EntityAggregator

    aggregator = EntityAggregator()
    no_speaker: dict[str, dict] = {}
    for config in configs:
        if any(n in cache.failures for n in config.detectors):
            continue
        predictions = {}
        for doc in gold:
            candidates = [e for n in sorted(config.detectors) for e in cache.get(n, doc.doc_id)]
            predictions[doc.doc_id] = aggregator.aggregate(candidates, doc.text).entities
        filtered_gold, filtered_pred = without_speaker_lines(gold, predictions)
        no_speaker[config.key] = evaluate(filtered_gold, filtered_pred).to_dict()

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "provenance": provenance(
            settings,
            {
                "generated_by": f"evaluation.cli sweep --configs {args.configs or 'all'}",
                "split": args.split,
                "qwen_enabled": settings.qwen.enabled,
                "qwen_skip_reason": (
                    None if settings.qwen.enabled else "disabled by default; no model pulled"
                ),
            },
        ),
        "dataset": dataset_summary(gold),
        "detector_seconds": {k: round(v, 4) for k, v in sorted(cache.seconds.items())},
        "detector_failures": dict(sorted(cache.failures.items())),
        "configs": [r.to_dict() for r in results],
        "excluding_speaker_lines": no_speaker,
    }

    (out_dir / "metrics.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8"
    )

    errors_dir = out_dir / "errors"
    errors_dir.mkdir(exist_ok=True)
    for result in results:
        if result.evaluation is None:
            continue
        for kind, items in (
            ("fp", result.evaluation.false_positives),
            ("fn", result.evaluation.false_negatives),
        ):
            path = errors_dir / f"{result.key}_{kind}.jsonl"
            path.write_text(
                "\n".join(json.dumps(e.to_dict(), ensure_ascii=True) for e in items) + "\n",
                encoding="utf-8",
            )

    markdown = render_markdown(payload)
    (out_dir / "report.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"\nWritten to {out_dir}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    gold = GoldSet.load(args.gold)
    gold = GoldSet(tuple(d for d in gold if d.labeler), gold.path)
    problems = gold.validate()
    for problem in problems:
        print(f"  {problem}")
    print(f"{len(gold)} documents, {gold.scored_span_count} scored spans")
    print(f"{len(problems)} problem(s)")
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="privacy-gateway-eval")
    sub = parser.add_subparsers(dest="command", required=True)

    sweep = sub.add_parser("sweep", help="run the detector configuration sweep")
    sweep.add_argument("--gold", type=Path, default=DEFAULT_GOLD)
    sweep.add_argument("--out", type=Path, default=DEFAULT_OUT)
    sweep.add_argument("--split", default=None, choices=("dev", "test"))
    sweep.add_argument("--configs", default=None, help="e.g. A,B,D,E")
    sweep.set_defaults(func=cmd_sweep)

    validate = sub.add_parser("validate", help="check the gold set")
    validate.add_argument("--gold", type=Path, default=DEFAULT_GOLD)
    validate.set_defaults(func=cmd_validate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
