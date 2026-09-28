"""Derive offset-anchored gold spans from the existing string labels.

The corpus carries 270 ``must_redact`` strings written by hand. Entity-level
scoring needs character offsets, and retyping 270 labels by hand would be both
tedious and a fresh source of error. Every one of those strings can be located
in its source mechanically, so this does that once and writes the result back
into the sidecar.

What it will not do is guess a type. A gold span labelled EMAIL that the
pipeline correctly redacts as a CREDENTIAL manufactures a false positive and a
false negative out of one right answer, so a value whose type cannot be
established from the pattern layer is labelled with the wildcard instead.

``--check`` re-validates that every stored offset still addresses the text it
claims, which is the guard against a fixture being edited without its labels.
It needs no model and runs in the fast suite.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pii.patterns import detect_patterns  # noqa: E402
from tools.scoring import WILDCARD_LABEL, GoldSpan  # noqa: E402

FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures"


def find_occurrences(source: str, value: str) -> list[tuple[int, int]]:
    """Every place ``value`` occurs, preferring whole-token matches.

    Whole-token first, so "Elena" does not match inside "Elenaville". The plain
    substring fallback exists for labels that are deliberately a prefix of a
    longer token -- a JWT is labelled by its first twenty characters, and a
    trailing word boundary will never match there.
    """
    spans = [
        (m.start(), m.end())
        for m in re.finditer(rf"(?<!\w){re.escape(value)}(?!\w)", source)
    ]
    if spans:
        return spans
    if " " in value:
        pattern_str = r"\s+".join(re.escape(tok) for tok in value.split())
        spans = [
            (m.start(), m.end())
            for m in re.finditer(rf"(?<!\w){pattern_str}(?!\w)", source)
        ]
        if spans:
            return spans
    return [(m.start(), m.end()) for m in re.finditer(re.escape(value), source)]


def infer_label(value: str) -> str:
    """The type of a labelled value, or the wildcard when it is not knowable.

    Only a pattern hit covering the whole value counts. A rule that matches
    part of it has identified something else inside it, which is not evidence
    about the value as a whole.
    """
    try:
        spans = detect_patterns(value)
    except Exception:  # a malformed probe value must not stop derivation
        return WILDCARD_LABEL
    for span in spans:
        if span.start == 0 and span.end == len(value):
            return span.label
    return WILDCARD_LABEL


def cluster_entities(expected: dict) -> dict[str, str]:
    """Map each value named in a ``same_entity`` group to a cluster id.

    Only values that appear in a group are clustered. Giving every other value
    its own id would assert that two surface forms of one person are different
    people whenever nobody wrote a group for them, and every correct merge
    would then be reported as a wrong merge.
    """
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for group in expected.get("same_entity", []):
        members = [m for m in group if isinstance(m, str)]
        for other in members[1:]:
            union(members[0], other)

    roots: dict[str, str] = {}
    out: dict[str, str] = {}
    for value in sorted(parent):
        root = find(value)
        if root not in roots:
            roots[root] = f"e{len(roots) + 1}"
        out[value] = roots[root]
    return out


def collapse_nested(spans: list[GoldSpan]) -> list[GoldSpan]:
    """Drop spans strictly inside a longer one, by offset.

    "Eleanor" is a label in its own right and also sits inside every
    "Eleanor Vance". Keeping both would make the full-name redaction match one
    and leave the other as a phantom miss. Containment is tested on offsets,
    not on strings, so a standalone "Eleanor" elsewhere in the document
    survives.
    """
    ordered = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
    kept: list[GoldSpan] = []
    for span in ordered:
        if any(k.start <= span.start and k.end >= span.end and k is not span for k in kept):
            continue
        kept.append(span)
    return sorted(kept, key=lambda s: s.start)


def derive(source: str, expected: dict) -> tuple[list[GoldSpan], list[str]]:
    clusters = cluster_entities(expected)
    warnings: list[str] = []
    spans: list[GoldSpan] = []

    for item in expected.get("must_redact", []):
        value = item["value"] if isinstance(item, dict) else item
        occurrences = find_occurrences(source, value)
        if not occurrences:
            warnings.append(f"not found in source: {value!r}")
            continue
        label = infer_label(value)
        if label == WILDCARD_LABEL and value in clusters:
            # Values grouped as one entity are names; the pattern layer has no
            # rule for them, but the grouping itself is the evidence.
            label = "PERSON"
        if label == WILDCARD_LABEL:
            warnings.append(f"type not inferable, using {WILDCARD_LABEL}: {value!r}")
        for start, end in occurrences:
            spans.append(
                GoldSpan(
                    start=start,
                    end=end,
                    label=label,
                    text=source[start:end],
                    entity=clusters.get(value, ""),
                    origin="derived",
                )
            )

    return collapse_nested(spans), warnings


def derive_negatives(source: str, expected: dict) -> list[dict]:
    """``must_keep`` values, anchored, as the seed of the over-redaction set."""
    out: list[dict] = []
    for value in expected.get("must_keep", []):
        for start, end in find_occurrences(source, value):
            out.append({"start": start, "end": end, "text": source[start:end], "reason": "must_keep"})
            break  # one anchor per value is enough to prove it was locatable
    return out


def load_pairs(
    only: str | None = None, *, directory: Path = FIXTURE_DIR
) -> list[tuple[str, Path, str, dict]]:
    pairs: list[tuple[str, Path, str, dict]] = []
    for expected_path in sorted(directory.glob("*.expected.json")):
        name = expected_path.name.removesuffix(".expected.json")
        if only and only != name:
            continue
        source_path = expected_path.with_name(f"{name}.txt")
        if not source_path.is_file():
            print(f"  ! missing source for {name}", file=sys.stderr)
            continue
        pairs.append(
            (
                name,
                expected_path,
                source_path.read_text(encoding="utf-8"),
                json.loads(expected_path.read_text(encoding="utf-8")),
            )
        )
    return pairs


def check(only: str | None = None, *, directory: Path = FIXTURE_DIR) -> int:
    """Validate stored offsets against the sources. No model required."""
    problems = 0
    checked = 0
    for name, _path, source, expected in load_pairs(only, directory=directory):
        gold_spans = expected.get("gold_spans")
        if gold_spans is None:
            print(f"  ! {name}: no gold_spans (run --write)")
            problems += 1
            continue
        for raw in gold_spans:
            span = GoldSpan.from_dict(raw)
            actual = source[span.start : span.end]
            if actual != span.text:
                print(f"  ! {name}: offset {span.start}:{span.end} is {actual!r}, expected {span.text!r}")
                problems += 1
            checked += 1

        # Coverage is tested by offset, not by string. A value that is always
        # part of a longer label -- "Sen" inside every "Ananya Sen" -- has no
        # span of its own after nesting collapse, and correctly so: redacting
        # the longer span already removes it. What must never happen is an
        # occurrence that no gold span covers.
        anchors = [(GoldSpan.from_dict(r).start, GoldSpan.from_dict(r).end) for r in gold_spans]
        for item in expected.get("must_redact", []):
            value = item["value"] if isinstance(item, dict) else item
            for start, end in find_occurrences(source, value):
                if not any(a <= start and b >= end for a, b in anchors):
                    print(f"  ! {name}: uncovered occurrence of {value!r} at {start}:{end}")
                    problems += 1

    print(f"checked {checked} gold spans across the corpus; {problems} problem(s)")
    return 1 if problems else 0


def write(only: str | None = None, *, directory: Path = FIXTURE_DIR) -> int:
    total_spans = 0
    total_warnings = 0
    for name, path, source, expected in load_pairs(only, directory=directory):
        spans, warnings = derive(source, expected)
        expected["schema"] = 2
        expected.setdefault("gold_complete", False)
        expected["gold_spans"] = [s.as_dict() for s in spans]
        expected.setdefault("gold_negatives", derive_negatives(source, expected))
        path.write_text(json.dumps(expected, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        total_spans += len(spans)
        total_warnings += len(warnings)
        flag = f"  ({len(warnings)} warning(s))" if warnings else ""
        print(f"  {name:48} {len(spans):4} spans{flag}")
        for warning in warnings:
            print(f"      - {warning}")

    print(f"\nwrote {total_spans} gold spans, {total_warnings} warning(s)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", default=None, help="restrict to one fixture")
    parser.add_argument("--write", action="store_true", help="derive and write gold_spans")
    parser.add_argument("--check", action="store_true", help="validate stored offsets")
    parser.add_argument(
        "--dir", default=None, help="corpus directory (default tests/fixtures)"
    )
    args = parser.parse_args()
    directory = Path(args.dir) if args.dir else FIXTURE_DIR

    if args.write:
        return write(args.only, directory=directory)
    if args.check:
        return check(args.only, directory=directory)
    parser.error("pass --write or --check")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
