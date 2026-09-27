"""Score the redactor against a labelled corpus.

Every previous round of fixes was validated by eyeballing the newest document,
so each one regressed something older. 95 of the 130 unit tests assert literals
from one specific transcript; they record what broke last time rather than
measuring whether anything generalises.

This scores every fixture at once and reports four things that matter:

* **recall** -- what fraction of the values that must be removed actually were.
  A miss here is a leak, and a leak is unrecoverable.
* **precision** -- what fraction of the text that must survive actually did.
  This is the number that has been quietly falling while recall was chased.
* **consistency** -- one placeholder per entity, one entity per placeholder.
* **integrity** -- brackets, quotes and line counts preserved.

Usage::

    uv run python tools/evaluate.py                # score everything
    uv run python tools/evaluate.py --only scenario_01_plain_meeting
    uv run python tools/evaluate.py --baseline     # rewrite the recorded baseline
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pii import PIIMiddleware  # noqa: E402

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
BASELINE_PATH = FIXTURE_DIR / "baseline.json"
PLACEHOLDER_RE = re.compile(r"\{\{([A-Z][A-Z0-9_]*_\d+)\}\}")


@dataclass
class DocumentScore:
    name: str
    leaks: list[str] = field(default_factory=list)
    over_redactions: list[str] = field(default_factory=list)
    expected_redactions: int = 0
    expected_keeps: int = 0
    split_entities: list[str] = field(default_factory=list)
    merged_placeholders: list[str] = field(default_factory=list)
    integrity: list[str] = field(default_factory=list)
    entities: int = 0

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
    def clean(self) -> bool:
        return not (
            self.leaks
            or self.over_redactions
            or self.split_entities
            or self.merged_placeholders
            or self.integrity
        )


def _contains(haystack: str, needle: str) -> bool:
    """Whole-token containment, so 'Elena' does not match 'Elenaville'."""
    return re.search(rf"(?<!\w){re.escape(needle)}(?!\w)", haystack) is not None


def score_document(name: str, source: str, expected: dict, middleware: PIIMiddleware) -> DocumentScore:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = middleware.analyze(source)

    sanitized = result.sanitized
    score = DocumentScore(name=name, entities=len(result.mapping))

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

    # Consistency: one placeholder per real entity, one value per placeholder.
    by_value: dict[str, set[str]] = {}
    for placeholder, value in result.mapping.items():
        by_value.setdefault(value, set()).add(placeholder)
    for value, placeholders in by_value.items():
        if len(placeholders) > 1:
            score.split_entities.append(f"{value!r} -> {sorted(placeholders)}")

    for group in expected.get("same_entity", []):
        placeholders = {
            placeholder
            for placeholder, value in result.mapping.items()
            if value in group
        }
        if len(placeholders) > 1:
            score.split_entities.append(f"{group} -> {sorted(placeholders)}")

    # Integrity: a redactor must not damage the document around the entities.
    # Balance, not absolute count: the parentheses in "+1 (555) 019-2834" are
    # part of the phone number and correctly vanish with it. What must never
    # happen is an unbalanced result.
    for opener, closer in (("(", ")"), ("[", "]"), ("{{", "}}")):
        if sanitized.count(opener) != sanitized.count(closer):
            score.integrity.append(f"unbalanced {opener}{closer}")
    if sanitized.count('"') % 2 != source.count('"') % 2:
        score.integrity.append("quote parity changed")
    if len(source.splitlines()) != len(sanitized.splitlines()):
        score.integrity.append("line count changed")
    if re.search(r"\}\}\w", sanitized) or re.search(r"\w\{\{", sanitized):
        score.integrity.append("placeholder glued mid-word")
    for match in re.finditer(r"\{\{([A-Z][A-Z0-9_]*_\d+)\}\}\s*\{\{\1\}\}", sanitized):
        score.integrity.append(f"placeholder emitted twice: {match.group(1)}")

    return score


def load_fixtures(only: str | None = None) -> list[tuple[str, str, dict]]:
    fixtures: list[tuple[str, str, dict]] = []
    for expected_path in sorted(FIXTURE_DIR.glob("*.expected.json")):
        name = expected_path.name.removesuffix(".expected.json")
        if only and only != name:
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Score redaction across the labelled corpus.")
    parser.add_argument("--only", default=None, help="score a single fixture")
    parser.add_argument("--profile", default=None, help="override the redaction profile")
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="record the current numbers as the regression baseline",
    )
    args = parser.parse_args()

    fixtures = load_fixtures(args.only)
    if not fixtures:
        print("No fixtures found. Add tests/fixtures/<name>.txt + <name>.expected.json")
        return 2

    kwargs = {"on_leak": "warn"}
    if args.profile:
        kwargs["profile"] = args.profile
    middleware = PIIMiddleware(**kwargs)

    scores = [score_document(name, source, expected, middleware) for name, source, expected in fixtures]

    print(f"{'document':38} {'recall':>7} {'prec':>7} {'ents':>5}  issues")
    print("-" * 86)
    total_leaks = 0
    for score in scores:
        issues: list[str] = []
        if score.leaks:
            issues.append(f"LEAK {score.leaks}")
        if score.over_redactions:
            issues.append(f"over {score.over_redactions}")
        if score.split_entities:
            issues.append(f"split {score.split_entities}")
        if score.integrity:
            issues.append(f"integrity {score.integrity}")
        total_leaks += len(score.leaks)
        marker = "ok" if score.clean else ""
        print(
            f"{score.name:38} {score.recall:7.2f} {score.precision:7.2f} "
            f"{score.entities:5}  {'; '.join(issues) or marker}"
        )

    macro_recall = sum(s.recall for s in scores) / len(scores)
    macro_precision = sum(s.precision for s in scores) / len(scores)
    print("-" * 86)
    print(
        f"{'MACRO AVERAGE':38} {macro_recall:7.2f} {macro_precision:7.2f}"
        f"        leaks={total_leaks}  clean={sum(s.clean for s in scores)}/{len(scores)}"
    )

    current = {
        "macro_recall": round(macro_recall, 4),
        "macro_precision": round(macro_precision, 4),
        "total_leaks": total_leaks,
        "per_document": {
            s.name: {"recall": round(s.recall, 4), "precision": round(s.precision, 4)}
            for s in scores
        },
    }

    if args.baseline:
        BASELINE_PATH.write_text(json.dumps(current, indent=2), encoding="utf-8")
        print(f"\nBaseline written to {BASELINE_PATH}")
        return 0

    if BASELINE_PATH.is_file():
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        regressions = [
            f"{name}: precision {baseline['per_document'][name]['precision']:.2f}"
            f" -> {current['per_document'][name]['precision']:.2f}"
            for name in current["per_document"]
            if name in baseline.get("per_document", {})
            and current["per_document"][name]["precision"]
            < baseline["per_document"][name]["precision"] - 1e-9
        ]
        if regressions:
            print("\nPRECISION REGRESSIONS vs baseline:")
            for line in regressions:
                print(f"  {line}")

    # A leak is a failure. Over-redaction is reported but does not gate.
    return 1 if total_leaks else 0


if __name__ == "__main__":
    raise SystemExit(main())
