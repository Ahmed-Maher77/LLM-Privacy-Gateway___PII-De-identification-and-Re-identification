"""Guards on the held-out corpus, plus the scored run itself.

The guards are the point. A held-out corpus is only held out for as long as
nobody reaches into it to make a failure go away, and "we agreed not to" is not
a control. These tests fail if a holdout value turns up in the package, if the
pools stop being disjoint from the tuned corpus, or if a generated document
has been edited by hand instead of regenerated.

They need no model and run in the fast suite. Only the scored run is slow.
"""

from __future__ import annotations

import json
import re
import warnings
from pathlib import Path

import pytest

from tools.make_holdout import GENERIC_TOKENS, POOLS, assert_disjoint, build, fixture_tokens
from tools.scoring import GoldSpan, align, check_assertions, predictions_from_result

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HOLDOUT_DIR = PROJECT_ROOT / "tests" / "holdout"
PII_DIR = PROJECT_ROOT / "pii"


def holdout_names() -> list[str]:
    return sorted(p.name.removesuffix(".expected.json") for p in HOLDOUT_DIR.glob("*.expected.json"))


def pool_values() -> list[str]:
    return [v for values in POOLS.values() for v in values]


class TestHoldoutIsHeldOut:
    def test_no_holdout_value_appears_in_the_package(self):
        """A holdout name inside pii/ means the holdout was tuned against.

        This is the specific failure it guards: a document fails, and the
        quickest way to make it pass is to paste the offending name into an
        allowlist, COMMON_WORDS or a pattern. That converts the only
        independent measurement in the repo into another fixture.
        """
        corpus = "\n".join(p.read_text(encoding="utf-8") for p in sorted(PII_DIR.rglob("*.py")))
        # Comments count. roster.py reasons about "Ms. Halloran" and "Mr.
        # Halloran" by name, so a holdout using that surname would be probing
        # a case the code was explicitly written against -- not held out at
        # all. That is why the honorific template uses a different name.
        #
        # common_word_names are exempt: they are chosen precisely for being
        # ordinary words, and spanfix.py discussing surnames that collide with
        # nouns is discussion of a general problem, not tuning on these values.
        exempt = set(POOLS["common_word_names"])
        leaked = sorted(
            value
            for value in pool_values()
            if value not in exempt
            for token in [value.split()[0].strip(".,")]
            if len(token) > 3
            and token.casefold() not in GENERIC_TOKENS
            and re.search(rf"\b{re.escape(token)}\b", corpus)
        )
        assert not leaked, f"holdout values found in pii/: {leaked}"

    def test_pools_are_disjoint_from_the_tuned_corpus(self):
        assert_disjoint(POOLS, fixture_tokens())

    def test_regeneration_is_byte_identical(self, tmp_path):
        """Stops a failing document being hand-edited into passing."""
        build(tmp_path)
        for name in holdout_names():
            for suffix in (".txt", ".expected.json"):
                committed = (HOLDOUT_DIR / f"{name}{suffix}").read_text(encoding="utf-8")
                regenerated = (tmp_path / f"{name}{suffix}").read_text(encoding="utf-8")
                assert committed == regenerated, f"{name}{suffix} was edited rather than regenerated"


class TestHoldoutLabels:
    def test_corpus_is_not_empty(self):
        assert len(holdout_names()) >= 12

    @pytest.mark.parametrize("name", holdout_names())
    def test_gold_is_exhaustive_by_construction(self, name):
        expected = json.loads((HOLDOUT_DIR / f"{name}.expected.json").read_text(encoding="utf-8"))
        assert expected["gold_complete"] is True
        assert all(s["origin"] == "generated" for s in expected["gold_spans"])

    @pytest.mark.parametrize("name", holdout_names())
    def test_offsets_address_the_text_they_claim(self, name):
        source = (HOLDOUT_DIR / f"{name}.txt").read_text(encoding="utf-8")
        expected = json.loads((HOLDOUT_DIR / f"{name}.expected.json").read_text(encoding="utf-8"))
        for raw in expected["gold_spans"]:
            span = GoldSpan.from_dict(raw)
            assert source[span.start : span.end] == span.text


@pytest.mark.slow
@pytest.mark.holdout
class TestHoldoutScored:
    """The scored run. Separate marker so a default run never touches it."""

    @pytest.fixture(scope="class")
    def middleware(self):
        from pii import PIIMiddleware

        return PIIMiddleware(on_leak="warn")

    @pytest.fixture(scope="class")
    def results(self, middleware):
        out = {}
        for name in holdout_names():
            source = (HOLDOUT_DIR / f"{name}.txt").read_text(encoding="utf-8")
            expected = json.loads((HOLDOUT_DIR / f"{name}.expected.json").read_text(encoding="utf-8"))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                out[name] = (source, expected, middleware.analyze(source))
        return out

    @pytest.mark.parametrize("name", holdout_names())
    def test_no_leaks(self, results, name):
        source, expected, result = results[name]
        gold = [GoldSpan.from_dict(r) for r in expected["gold_spans"]]
        alignment = align(gold, predictions_from_result(result), gold_complete=True)
        assert not alignment.false_negatives, [g.text for g in alignment.false_negatives]

    @pytest.mark.parametrize("name", holdout_names())
    def test_no_partial_redactions(self, results, name):
        source, expected, result = results[name]
        gold = [GoldSpan.from_dict(r) for r in expected["gold_spans"]]
        alignment = align(gold, predictions_from_result(result), gold_complete=True)
        leaks = alignment.partial_substantive(source)
        assert not leaks, [m.substantive_remainder(source) for m in leaks]

    @pytest.mark.parametrize("name", holdout_names())
    def test_merge_assertions_hold(self, results, name):
        source, expected, result = results[name]
        gold = [GoldSpan.from_dict(r) for r in expected["gold_spans"]]
        assertions = dict(expected.get("assertions", {}))
        assertions["_source"] = source
        assert check_assertions(result, gold, assertions) == []
