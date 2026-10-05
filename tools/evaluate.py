"""Score the redactor against a labelled corpus.

Every previous round of fixes was validated by eyeballing the newest document,
so each one regressed something older. This scores every fixture at once.

Scoring is tiered, cheapest first:

* **Tier 1 -- substring gate.** Did every ``must_redact`` value disappear and
  every ``must_keep`` value survive? Cheap to read, cheap to write, and a leak
  here is the one unconditional failure. It cannot measure anything outside
  those lists, which is why it is a gate and not the headline.
* **Tier 2 -- entity-level.** Every span the pipeline actually replaced is
  aligned against offset-anchored gold, giving micro precision, recall and F1
  per label, plus the specific false redactions behind the number. This is the
  headline, and it only counts false positives on documents that declare
  ``gold_complete``.

Alongside both: cluster metrics (was each entity merged correctly), integrity
(brackets, quotes and line counts preserved), JSON validity, and latency.

Usage::

    uv run python tools/evaluate.py                     # score everything
    uv run python tools/evaluate.py --select "prod_*"   # one family
    uv run python tools/evaluate.py --show-fp 0         # every false redaction
    uv run python tools/evaluate.py --triage            # group them for labelling
    uv run python tools/evaluate.py --report            # write markdown + json
    uv run python tools/evaluate.py --baseline          # rewrite the baseline
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import statistics
import sys
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

from pii import PIIMiddleware  # noqa: E402
from pii.policy import _normalize, describe_policy  # noqa: E402
from tools.scoring import (  # noqa: E402
    CRITICAL_LABELS,
    Alignment,
    ClusterScore,
    Counts,
    GoldSpan,
    align,
    boundary_exact_rate,
    cluster_metrics,
    counts_by_label,
    integrity_issues,
    json_blocks_are_valid,
    merge_counts,
    predictions_from_result,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures"
BASELINE_PATH = FIXTURE_DIR / "baseline.json"
DEFAULT_SANITIZED_DIR = PROJECT_ROOT / "reports" / "sanitized"
DEFAULT_REPORT_MD = PROJECT_ROOT / "reports" / "evaluation_report.md"
DEFAULT_REPORT_JSON = PROJECT_ROOT / "reports" / "evaluation.json"
PLACEHOLDER_RE = re.compile(r"\{\{([A-Z][A-Z0-9_]*_\d+)\}\}")

# What a regression is. Pinning every number at 1.0, as the previous baseline
# did, detects any drop but conveys no headroom and cannot distinguish a
# rounding change from a lost identifier.
GATES = {
    "micro_f1_drop": 0.02,
    "document_f1_drop": 0.05,
}


@dataclass
class DocumentScore:
    name: str
    # --- Tier 1, unchanged: these names are part of the imported API ---
    leaks: list[str] = field(default_factory=list)
    over_redactions: list[str] = field(default_factory=list)
    expected_redactions: int = 0
    expected_keeps: int = 0
    split_entities: list[str] = field(default_factory=list)
    merged_placeholders: list[str] = field(default_factory=list)
    integrity: list[str] = field(default_factory=list)
    entities: int = 0
    # --- Tier 2 ---
    alignment: Alignment | None = None
    by_label: dict[str, Counts] = field(default_factory=dict)
    cluster: ClusterScore | None = None
    gold_complete: bool = False
    gold_count: int = 0
    latency_s: float = 0.0
    status: str = "clean"
    json_valid: bool | None = None
    error: str | None = None
    sanitized: str = ""
    source: str = ""
    mapping: dict[str, str] = field(default_factory=dict)

    @property
    def recall(self) -> float:
        if not self.expected_redactions:
            return 1.0
        return 1 - len(self.leaks) / self.expected_redactions

    @property
    def precision(self) -> float:
        if not self.expected_keeps:
            return 1.0
        return 1 - len(self.over_redactions) / self.expected_keeps

    @property
    def counts(self) -> Counts:
        if self.alignment is None:
            return Counts()
        return Counts(
            tp=self.alignment.tp,
            fp=self.alignment.fp,
            fn=self.alignment.fn,
            unverified=len(self.alignment.unverified),
            tp_pred=self.alignment.tp_pred,
        )

    @property
    def span_precision(self) -> float:
        return self.counts.precision

    @property
    def span_recall(self) -> float:
        return self.counts.recall

    @property
    def f1(self) -> float:
        return self.counts.f1

    @property
    def measured(self) -> bool:
        """False for a zero-PII control, which must not average in as 1.0."""
        return self.counts.defined

    @property
    def partial(self) -> list:
        """Every partial redaction, including trivial boundary ones."""
        return [] if self.alignment is None else self.alignment.partial

    @property
    def partial_leaks(self) -> list:
        """Partial redactions where identifying content survived. Gated."""
        if self.alignment is None:
            return []
        return self.alignment.partial_substantive(self.source)

    @property
    def clean(self) -> bool:
        return not (
            self.leaks
            or self.over_redactions
            or self.split_entities
            or self.merged_placeholders
            or self.integrity
        )

    @property
    def hard_failures(self) -> list[str]:
        """Failures that gate regardless of what the aggregate does."""
        problems: list[str] = []
        if self.error:
            problems.append(f"analyze() raised: {self.error}")
        if self.leaks:
            problems.append(f"{len(self.leaks)} leak(s)")
        if self.partial_leaks:
            problems.append(
                f"{len(self.partial_leaks)} partial redaction(s) leaving content: "
                + "; ".join(
                    sorted({m.substantive_remainder(self.source)[:48] for m in self.partial_leaks})
                )
            )
        if self.cluster and self.cluster.wrong_merges:
            problems.append(f"{len(self.cluster.wrong_merges)} wrong merge(s)")
        if self.integrity:
            problems.append(f"integrity: {'; '.join(self.integrity)}")
        return problems


def _contains(haystack: str, needle: str) -> bool:
    """Whole-token containment, so 'Elena' does not match 'Elenaville'."""
    return re.search(rf"(?<!\w){re.escape(needle)}(?!\w)", haystack) is not None


def score_document(
    name: str,
    source: str,
    expected: dict,
    middleware: PIIMiddleware,
    *,
    entity_level: bool = True,
    repeat: int = 1,
) -> DocumentScore:
    score = DocumentScore(name=name, source=source)

    timings: list[float] = []
    result = None
    for _ in range(max(1, repeat)):
        started = time.perf_counter()
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                result = middleware.analyze(source)
        except Exception as exc:  # noqa: BLE001 -- one bad document must not
            # abort the sweep. analyze() raises LeakDetected, ReviewRequired,
            # PlaceholderInjection and AssertionError by design; before this,
            # a single raising fixture took the whole corpus number with it.
            score.error = f"{type(exc).__name__}: {exc}"
            return score
        timings.append(time.perf_counter() - started)

    # Median, and drop the first pass when repeating: it carries model warmup.
    score.latency_s = statistics.median(timings[1:] or timings)

    sanitized = result.sanitized
    score.sanitized = sanitized
    score.mapping = dict(result.mapping)
    score.entities = len(result.mapping)
    score.status = result.status

    # --- Tier 1: the substring gate ---------------------------------------
    must_redact = expected.get("must_redact", [])
    score.expected_redactions = len(must_redact)
    for item in must_redact:
        value = item["value"] if isinstance(item, dict) else item
        if _contains(sanitized, value):
            score.leaks.append(value)

    must_keep = expected.get("must_keep", [])
    score.expected_keeps = len(must_keep)
    for value in must_keep:
        if not _contains(sanitized, value):
            score.over_redactions.append(value)

    by_value: dict[str, set[str]] = {}
    for placeholder, value in result.mapping.items():
        by_value.setdefault(value, set()).add(placeholder)
    for value, placeholders in by_value.items():
        if len(placeholders) > 1:
            score.split_entities.append(f"{value!r} -> {sorted(placeholders)}")

    score.integrity = integrity_issues(source, sanitized)
    valid, _errors = json_blocks_are_valid(sanitized)
    score.json_valid = valid

    # --- Tier 2: entity-level ---------------------------------------------
    if entity_level:
        gold = [GoldSpan.from_dict(raw) for raw in expected.get("gold_spans", [])]
        score.gold_count = len(gold)
        score.gold_complete = bool(expected.get("gold_complete", False))
        predictions = predictions_from_result(result)
        score.alignment = align(gold, predictions, gold_complete=score.gold_complete)
        score.by_label = counts_by_label(score.alignment)
        score.cluster = cluster_metrics(score.alignment.matches)

    return score


def load_fixtures(only: str | None = None, *, select: str | None = None, directory: Path | None = None):
    """Fixtures as ``(name, source, expected)``. Signature kept for callers."""
    fixtures: list[tuple[str, str, dict]] = []
    root = directory or FIXTURE_DIR
    for expected_path in sorted(root.glob("*.expected.json")):
        name = expected_path.name.removesuffix(".expected.json")
        if only and only != name:
            continue
        if select and not fnmatch.fnmatch(name, select):
            continue
        source_path = expected_path.with_name(f"{name}.txt")
        if not source_path.is_file():
            print(f"  ! missing source for {name}", file=sys.stderr)
            continue
        fixtures.append(
            (
                name,
                source_path.read_text(encoding="utf-8"),
                json.loads(expected_path.read_text(encoding="utf-8")),
            )
        )
    return fixtures


def load_baseline(path: Path = BASELINE_PATH) -> dict:
    """Read a baseline, upgrading schema 1 in memory so old files still load."""
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") == 2:
        return data
    return {
        "schema": 2,
        "micro": {},
        "macro": {
            "recall": data.get("macro_recall", 0.0),
            "precision": data.get("macro_precision", 0.0),
        },
        "per_document": data.get("per_document", {}),
        "_upgraded_from": 1,
    }


def corpus_counts(scores: list[DocumentScore]) -> Counts:
    total = Counts()
    for score in scores:
        c = score.counts
        total = Counts(
            tp=total.tp + c.tp,
            fp=total.fp + c.fp,
            fn=total.fn + c.fn,
            unverified=total.unverified + c.unverified,
            tp_pred=total.justified + c.justified,
        )
    return total


def false_redaction_groups(scores: list[DocumentScore]) -> list[dict]:
    """False positives grouped by document, label and surface.

    One line per distinct thing wrongly redacted, not one per occurrence, so
    the list reads as a to-do rather than a transcript.
    """
    groups: dict[tuple[str, str, str], dict] = {}
    for score in scores:
        if score.alignment is None:
            continue
        for span in score.alignment.false_positives:
            key = (score.name, span.label, _normalize(span.text))
            entry = groups.setdefault(
                key,
                {
                    "document": score.name,
                    "label": span.label,
                    "text": span.text,
                    "source": span.source,
                    "count": 0,
                    "line": 1 + score.source.count("\n", 0, span.start),
                    "context": _context(score.source, span.start, span.end),
                },
            )
            entry["count"] += 1
    return sorted(groups.values(), key=lambda g: (-g["count"], g["document"], g["label"]))


def unverified_groups(scores: list[DocumentScore]) -> list[dict]:
    """The triage queue: predictions on documents whose gold is not exhaustive."""
    groups: dict[tuple[str, str, str], dict] = {}
    for score in scores:
        if score.alignment is None:
            continue
        for span in score.alignment.unverified:
            key = (score.name, span.label, _normalize(span.text))
            entry = groups.setdefault(
                key,
                {
                    "document": score.name,
                    "label": span.label,
                    "text": span.text,
                    "source": span.source,
                    "count": 0,
                    "start": span.start,
                    "end": span.end,
                    "line": 1 + score.source.count("\n", 0, span.start),
                    "context": _context(score.source, span.start, span.end),
                },
            )
            entry["count"] += 1
    return sorted(groups.values(), key=lambda g: (g["document"], -g["count"], g["label"]))


def _context(source: str, start: int, end: int, width: int = 40) -> str:
    left = source[max(0, start - width) : start].replace("\n", " ")
    hit = source[start:end].replace("\n", " ")
    right = source[end : end + width].replace("\n", " ")
    return f"...{left}[{hit}]{right}..."


# --- Printing ---------------------------------------------------------------

def print_document_table(scores: list[DocumentScore]) -> None:
    header = (
        f"{'document':40} {'rec':>5} {'prec':>5} {'F1':>6} "
        f"{'TP':>4} {'FP':>4} {'FN':>4} {'unv':>4} {'ents':>5} {'ms':>7}  issues"
    )
    print(header)
    print("-" * len(header))
    for score in scores:
        issues: list[str] = []
        if score.error:
            issues.append(f"ERROR {score.error}")
        if score.leaks:
            issues.append(f"LEAK {score.leaks}")
        if score.over_redactions:
            issues.append(f"over {score.over_redactions}")
        if score.partial_leaks:
            issues.append(
                "PARTIAL-LEAK "
                + str(sorted({m.substantive_remainder(score.source)[:40] for m in score.partial_leaks}))
            )
        elif score.partial:
            issues.append(f"partial-boundary x{len(score.partial)}")
        if score.cluster and score.cluster.wrong_merges:
            issues.append(f"WRONG-MERGE {score.cluster.wrong_merges}")
        if score.cluster and score.cluster.missed_merges:
            issues.append(f"split {score.cluster.missed_merges}")
        if score.integrity:
            issues.append(f"integrity {score.integrity}")
        if score.json_valid is False:
            issues.append("invalid JSON")
        if not score.gold_complete:
            issues.append("gold not exhaustive")

        c = score.counts
        f1 = f"{score.f1:6.3f}" if score.measured else "   n/a"
        print(
            f"{score.name:40} {score.recall:5.2f} {score.precision:5.2f} {f1} "
            f"{c.tp:4} {c.fp:4} {c.fn:4} {c.unverified:4} {score.entities:5} "
            f"{score.latency_s * 1000:7.0f}  {'; '.join(issues) or 'ok'}"
        )


def print_label_table(scores: list[DocumentScore]) -> None:
    merged = merge_counts(s.by_label for s in scores)
    if not merged:
        return
    print()
    header = f"{'label':22} {'P':>7} {'R':>7} {'F1':>7} {'TP':>5} {'FP':>5} {'FN':>5} {'unv':>5}"
    print(header)
    print("-" * len(header))
    for label, counts in merged.items():
        print(
            f"{label:22} {counts.precision:7.3f} {counts.recall:7.3f} {counts.f1:7.3f} "
            f"{counts.tp:5} {counts.fp:5} {counts.fn:5} {counts.unverified:5}"
        )
    print("-" * len(header))


def print_false_redactions(scores: list[DocumentScore], limit: int) -> None:
    groups = false_redaction_groups(scores)
    if not groups:
        return
    print(f"\nFALSE REDACTIONS ({len(groups)} distinct; predictions with no gold span)")
    shown = groups if limit == 0 else groups[:limit]
    for g in shown:
        print(
            f"  {g['document']:34} {g['label']:14} {g['text']!r:28} x{g['count']:<3} "
            f"src={g['source']:8} L{g['line']}"
        )
        print(f"      {g['context']}")
    if limit and len(groups) > limit:
        print(f"  ... {len(groups) - limit} more (use --show-fp 0)")


def print_triage(scores: list[DocumentScore], limit: int) -> None:
    groups = unverified_groups(scores)
    if not groups:
        print("\nNothing to triage: every document declares exhaustive gold.")
        return
    print(f"\nTRIAGE QUEUE ({len(groups)} distinct predictions on non-exhaustive documents)")
    print("Resolve each into gold_spans (it was PII) or gold_negatives (over-redaction).")
    current = None
    shown = groups if limit == 0 else groups[:limit]
    for g in shown:
        if g["document"] != current:
            current = g["document"]
            print(f"\n  == {current} ==")
        print(f"    {g['label']:14} {g['text']!r:30} x{g['count']:<3} src={g['source']:8} L{g['line']} @{g['start']}:{g['end']}")
        print(f"        {g['context']}")
    if limit and len(groups) > limit:
        print(f"\n  ... {len(groups) - limit} more (use --show-fp 0)")


def print_summary(scores: list[DocumentScore]) -> tuple[Counts, int]:
    total_leaks = sum(len(s.leaks) for s in scores)
    measured = [s for s in scores if s.measured]
    micro = corpus_counts(scores)

    macro_recall = sum(s.recall for s in scores) / len(scores)
    macro_precision = sum(s.precision for s in scores) / len(scores)
    macro_f1 = sum(s.f1 for s in measured) / len(measured) if measured else 0.0

    print()
    print(f"{'TIER 1 (substring gate)':40} recall={macro_recall:.3f} precision={macro_precision:.3f} leaks={total_leaks}")
    print(
        f"{'TIER 2 (entity-level, headline)':40} P={micro.precision:.3f} R={micro.recall:.3f} "
        f"F1={micro.f1:.3f}  TP={micro.tp} FP={micro.fp} FN={micro.fn} unverified={micro.unverified}"
    )
    print(f"{'  macro F1 over measured documents':40} {macro_f1:.3f} ({len(measured)}/{len(scores)} documents measured)")

    exhaustive = sum(1 for s in scores if s.gold_complete)
    print(f"{'  gold_complete':40} {exhaustive}/{len(scores)} documents")
    if micro.unverified:
        print(
            f"  NOTE: {micro.unverified} prediction(s) are unverified and excluded from precision."
            f" Precision is a lower bound until gold_complete is set everywhere."
        )

    all_matches = [m for s in scores if s.alignment for m in s.alignment.matches]
    print(f"{'  boundary exact rate':40} {boundary_exact_rate(all_matches):.3f}")

    hard = [(s.name, s.hard_failures) for s in scores if s.hard_failures]
    if hard:
        print("\nHARD FAILURES")
        for name, problems in hard:
            print(f"  {name}: {'; '.join(problems)}")
    return micro, total_leaks


# --- Baseline ---------------------------------------------------------------

def build_baseline(scores: list[DocumentScore], middleware: PIIMiddleware, init_s: float) -> dict:
    micro = corpus_counts(scores)
    merged = merge_counts(s.by_label for s in scores)
    measured = [s for s in scores if s.measured]
    all_matches = [m for s in scores if s.alignment for m in s.alignment.matches]
    return {
        "schema": 2,
        "profile": middleware.profile,
        "policy": describe_policy(
            middleware.profile, middleware.entities, custom_labels=middleware._custom_labels
        ),
        "detectors": middleware.describe_detectors(),
        "init_seconds": round(init_s, 3),
        "corpus": {
            "documents": len(scores),
            "gold_spans": sum(s.gold_count for s in scores),
            "gold_complete": sum(1 for s in scores if s.gold_complete),
        },
        "micro": {
            "precision": round(micro.precision, 4),
            "recall": round(micro.recall, 4),
            "f1": round(micro.f1, 4),
            "tp": micro.tp,
            "fp": micro.fp,
            "fn": micro.fn,
            "unverified": micro.unverified,
        },
        "macro": {
            "recall": round(sum(s.recall for s in scores) / len(scores), 4),
            "precision": round(sum(s.precision for s in scores) / len(scores), 4),
            "f1": round(sum(s.f1 for s in measured) / len(measured), 4) if measured else 0.0,
        },
        "boundary_exact_rate": round(boundary_exact_rate(all_matches), 4),
        "by_label": {
            label: {
                "precision": round(c.precision, 4),
                "recall": round(c.recall, 4),
                "f1": round(c.f1, 4),
                "tp": c.tp,
                "fp": c.fp,
                "fn": c.fn,
            }
            for label, c in merged.items()
        },
        "total_leaks": sum(len(s.leaks) for s in scores),
        "per_document": {
            s.name: {
                "recall": round(s.recall, 4),
                "precision": round(s.precision, 4),
                "f1": round(s.f1, 4),
                "span_precision": round(s.span_precision, 4),
                "span_recall": round(s.span_recall, 4),
                "tp": s.counts.tp,
                "fp": s.counts.fp,
                "fn": s.counts.fn,
                "unverified": s.counts.unverified,
                "entities": s.entities,
                "gold_complete": s.gold_complete,
                "measured": s.measured,
                "status": s.status,
            }
            for s in scores
        },
    }


def regressions_against(scores: list[DocumentScore], baseline: dict) -> list[str]:
    """Every gate that a run violates, as readable lines."""
    problems: list[str] = []
    if not baseline:
        return problems

    micro = corpus_counts(scores)
    base_micro = baseline.get("micro", {})
    if base_micro:
        drop = base_micro.get("f1", 0.0) - micro.f1
        if drop > GATES["micro_f1_drop"]:
            problems.append(f"micro F1 {base_micro['f1']:.3f} -> {micro.f1:.3f} (drop {drop:.3f})")

    merged = merge_counts(s.by_label for s in scores)
    for label, base in baseline.get("by_label", {}).items():
        if label not in CRITICAL_LABELS:
            continue
        now = merged.get(label)
        if now is None:
            continue
        if now.recall < base.get("recall", 0.0) - 1e-9:
            problems.append(
                f"{label} recall {base['recall']:.3f} -> {now.recall:.3f} (critical label)"
            )

    per_doc = baseline.get("per_document", {})
    for score in scores:
        base = per_doc.get(score.name)
        if not base or not score.measured:
            continue
        if "f1" in base and score.f1 < base["f1"] - GATES["document_f1_drop"]:
            problems.append(f"{score.name}: F1 {base['f1']:.3f} -> {score.f1:.3f}")
        if score.precision < base.get("precision", 0.0) - 1e-9:
            problems.append(
                f"{score.name}: substring precision {base['precision']:.2f} -> {score.precision:.2f}"
            )
    return problems


def _entity_override(raw: str) -> tuple[str, bool]:
    """Parse "KEY=true"/"KEY=false" for --entity.

    Key validation is left to ``PIIMiddleware`` itself, so a typo raises the
    same error here as it would from a Python caller.
    """
    key, sep, value = raw.partition("=")
    normalized = value.strip().casefold()
    if not sep or normalized not in {"true", "false"}:
        raise argparse.ArgumentTypeError(f"expected KEY=true|false, got {raw!r}")
    return key.strip(), normalized == "true"


def main() -> int:
    parser = argparse.ArgumentParser(description="Score redaction across the labelled corpus.")
    parser.add_argument("--only", default=None, help="score a single fixture by exact name")
    parser.add_argument("--select", default=None, help="glob over fixture names, e.g. 'prod_*'")
    parser.add_argument("--dir", default=None, help="corpus directory (default tests/fixtures)")
    parser.add_argument("--profile", default=None, help="override the redaction profile")
    parser.add_argument(
        "--entity",
        action="append",
        type=_entity_override,
        default=[],
        dest="entities",
        metavar="KEY=true|false",
        help="Override one entity type's redaction (repeatable), e.g. "
        "--entity duration=true --entity url=false.",
    )
    parser.add_argument(
        "--fixed-name",
        action="append",
        default=[],
        dest="fixed_names",
        metavar="NAME",
        help="Mask this name wherever it appears (repeatable).",
    )
    parser.add_argument("--repeat", type=int, default=1, help="runs per document; median reported")
    parser.add_argument("--show-fp", type=int, default=10, help="false redactions to print; 0 = all")
    parser.add_argument("--triage", action="store_true", help="list unverified predictions for labelling")
    parser.add_argument("--report", action="store_true", help="write markdown and json reports")
    parser.add_argument("--report-md", default=str(DEFAULT_REPORT_MD))
    parser.add_argument("--report-json", default=str(DEFAULT_REPORT_JSON))
    parser.add_argument("--sanitized-dir", default=None, help="write sanitized output here")
    parser.add_argument("--include-secrets", action="store_true", help="unmask PII in the report")
    parser.add_argument("--baseline", action="store_true", help="record the current numbers as the baseline")
    parser.add_argument("--baseline-path", default=str(BASELINE_PATH))
    args = parser.parse_args()

    directory = Path(args.dir) if args.dir else FIXTURE_DIR
    fixtures = load_fixtures(args.only, select=args.select, directory=directory)
    if not fixtures:
        print(f"No fixtures found in {directory}. Add <name>.txt + <name>.expected.json")
        return 2

    kwargs = {"on_leak": "warn"}
    if args.profile:
        kwargs["profile"] = args.profile
    if args.entities:
        kwargs["entities"] = dict(args.entities)
    if args.fixed_names:
        kwargs["fixed_names"] = args.fixed_names
    started = time.perf_counter()
    middleware = PIIMiddleware(**kwargs)
    init_s = time.perf_counter() - started

    scores = [
        score_document(name, source, expected, middleware, repeat=args.repeat)
        for name, source, expected in fixtures
    ]

    print_document_table(scores)
    print_label_table(scores)
    micro, total_leaks = print_summary(scores)
    if args.triage:
        print_triage(scores, args.show_fp)
    else:
        print_false_redactions(scores, args.show_fp)

    if args.sanitized_dir:
        out_dir = Path(args.sanitized_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for score in scores:
            if score.sanitized:
                (out_dir / f"{score.name}.sanitized.txt").write_text(score.sanitized, encoding="utf-8")
        print(f"\nSanitized output written to {out_dir}")

    baseline_path = Path(args.baseline_path)
    current = build_baseline(scores, middleware, init_s)

    if args.report:
        from tools.report import write_reports

        write_reports(
            scores,
            current,
            markdown_path=Path(args.report_md),
            json_path=Path(args.report_json),
            include_secrets=args.include_secrets,
        )

    if args.baseline:
        baseline_path.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        print(f"\nBaseline written to {baseline_path}")
        return 0

    problems = regressions_against(scores, load_baseline(baseline_path))
    if problems:
        print("\nREGRESSIONS vs baseline:")
        for line in problems:
            print(f"  {line}")

    # A leak, a partial redaction, a wrong merge or a crash is a failure.
    # Over-redaction is reported and gated through the baseline, not here.
    hard = sum(1 for s in scores if s.hard_failures)
    return 1 if (total_leaks or hard or problems) else 0


if __name__ == "__main__":
    raise SystemExit(main())
