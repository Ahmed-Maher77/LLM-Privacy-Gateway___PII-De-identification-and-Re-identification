"""Guards on the evaluation corpus itself. No model, no inference.

These catch the two ways the measurement quietly stopped meaning anything
before: a second copy of the corpus scored by a second harness with different
matching rules, and labels drifting out of alignment with the text they
describe.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.derive_gold_spans import FIXTURE_DIR, check, find_occurrences
from tools.scoring import GoldSpan

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HOLDOUT_DIR = PROJECT_ROOT / "tests" / "holdout"


def fixture_names() -> list[str]:
    return sorted(p.name.removesuffix(".expected.json") for p in FIXTURE_DIR.glob("*.expected.json"))


class TestCorpusLayout:
    def test_one_corpus_root_only(self):
        """Two copies of one corpus is how two scorers drifted apart.

        test_data/production_simulations/ held byte-identical duplicates of the
        prod_* fixtures, scored by a second harness whose matching rules
        differed from this one's. Either copy could be edited alone.
        """
        roots = {
            p.parent
            for p in PROJECT_ROOT.rglob("*.expected.json")
            if ".venv" not in p.parts and "node_modules" not in p.parts
        }
        assert roots <= {FIXTURE_DIR, HOLDOUT_DIR}, f"unexpected corpus root(s): {roots}"

    def test_every_fixture_has_a_source(self):
        for name in fixture_names():
            assert (FIXTURE_DIR / f"{name}.txt").is_file(), f"{name} has labels but no source"


class TestGoldSpans:
    def test_offsets_address_the_text_they_claim(self):
        """The guard against a fixture being edited without its labels."""
        assert check() == 0

    @pytest.mark.parametrize("name", fixture_names())
    def test_gold_spans_are_present_and_well_formed(self, name):
        expected = json.loads((FIXTURE_DIR / f"{name}.expected.json").read_text(encoding="utf-8"))
        assert "gold_spans" in expected, f"{name} has no gold_spans; run derive_gold_spans.py --write"
        for raw in expected["gold_spans"]:
            span = GoldSpan.from_dict(raw)
            assert span.end > span.start
            assert span.text

    @pytest.mark.parametrize("name", fixture_names())
    def test_gold_spans_do_not_nest(self, name):
        """A label inside another label double-counts one redaction."""
        expected = json.loads((FIXTURE_DIR / f"{name}.expected.json").read_text(encoding="utf-8"))
        spans = sorted(
            (GoldSpan.from_dict(r) for r in expected["gold_spans"]),
            key=lambda s: (s.start, s.end),
        )
        for i, a in enumerate(spans):
            for b in spans[i + 1 :]:
                if b.start >= a.end:
                    break
                assert not (a.start <= b.start and a.end >= b.end), f"{name}: {b.text!r} nests in {a.text!r}"

    @pytest.mark.parametrize("name", fixture_names())
    def test_every_must_redact_occurrence_is_covered(self, name):
        source = (FIXTURE_DIR / f"{name}.txt").read_text(encoding="utf-8")
        expected = json.loads((FIXTURE_DIR / f"{name}.expected.json").read_text(encoding="utf-8"))
        anchors = [(GoldSpan.from_dict(r).start, GoldSpan.from_dict(r).end) for r in expected["gold_spans"]]
        for item in expected.get("must_redact", []):
            value = item["value"] if isinstance(item, dict) else item
            for start, end in find_occurrences(source, value):
                assert any(a <= start and b >= end for a, b in anchors), (
                    f"{name}: {value!r} at {start}:{end} has no gold span"
                )


class TestGoldCompleteness:
    def test_gold_complete_is_declared_explicitly(self):
        """Absent means 'nobody has triaged this', which must not read as done."""
        for name in fixture_names():
            expected = json.loads((FIXTURE_DIR / f"{name}.expected.json").read_text(encoding="utf-8"))
            assert isinstance(expected.get("gold_complete"), bool), f"{name} does not declare gold_complete"
