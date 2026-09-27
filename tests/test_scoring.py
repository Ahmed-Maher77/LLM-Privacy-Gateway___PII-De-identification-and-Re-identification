"""Unit tests for entity-level scoring.

Synthetic spans throughout: no model, no fixtures, no I/O. The point is that
the arithmetic of the metric is gated on every change, not only on the slow
corpus run where a scoring bug would be indistinguishable from a detection
regression.
"""

from __future__ import annotations

import pytest

from pii.spans import Span
from pii.vault import ESCAPE_LABEL
from tools.scoring import (
    WILDCARD_LABEL,
    Alignment,
    Counts,
    GoldSpan,
    PredSpan,
    align,
    boundary_exact_rate,
    cluster_metrics,
    counts_by_label,
    extract_json_blocks,
    integrity_issues,
    json_blocks_are_valid,
    labels_compatible,
    merge_counts,
    predictions_from_result,
    prf,
)


def gold(start, end, label="PERSON", text="x", entity="") -> GoldSpan:
    return GoldSpan(start=start, end=end, label=label, text=text, entity=entity)


def pred(start, end, label="PERSON", text="x", identity=None) -> PredSpan:
    return PredSpan(start=start, end=end, label=label, text=text, identity=identity)


class FakeResult:
    """Stands in for AnonymizationResult without importing the middleware."""

    def __init__(self, spans, sanitized="", escapes=None):
        self.spans = spans
        self.sanitized = sanitized
        self.escapes = escapes or {}


class TestLabelCompatibility:
    def test_identical_labels_match(self):
        assert labels_compatible("EMAIL", "EMAIL")

    def test_unrelated_labels_do_not_match(self):
        assert not labels_compatible("EMAIL", "PERSON")

    def test_wildcard_gold_matches_anything(self):
        assert labels_compatible(WILDCARD_LABEL, "CREDIT_CARD")

    @pytest.mark.parametrize(
        "gold_label,pred_label",
        [("ADDRESS", "LOCATION"), ("BANK_ACCOUNT", "IBAN"), ("DOB", "DATE")],
    )
    def test_equivalent_labels_match(self, gold_label, pred_label):
        assert labels_compatible(gold_label, pred_label)


class TestAlign:
    def test_exact_match_is_a_true_positive(self):
        a = align([gold(0, 5)], [pred(0, 5)], gold_complete=True)
        assert (a.tp, a.fp, a.fn) == (1, 0, 0)
        assert a.matches[0].exact

    def test_prediction_wider_than_gold_still_matches(self):
        """'Dr. Aris Thorne' redacted against gold 'Aris Thorne'."""
        a = align([gold(4, 15)], [pred(0, 15)], gold_complete=True)
        assert (a.tp, a.fp, a.fn) == (1, 0, 0)
        assert a.matches[0].contains
        assert not a.matches[0].exact

    def test_unmatched_prediction_is_a_false_positive_when_gold_is_complete(self):
        a = align([], [pred(0, 5)], gold_complete=True)
        assert a.fp == 1
        assert a.unverified == []

    def test_unmatched_prediction_is_unverified_when_gold_is_incomplete(self):
        """The whole point: an unlabelled document cannot yield a precision."""
        a = align([], [pred(0, 5)], gold_complete=False)
        assert a.fp == 0
        assert len(a.unverified) == 1

    def test_missed_gold_is_a_false_negative(self):
        a = align([gold(0, 5)], [], gold_complete=True)
        assert (a.tp, a.fp, a.fn) == (0, 0, 1)

    def test_label_mismatch_does_not_match(self):
        a = align([gold(0, 5, "EMAIL")], [pred(0, 5, "PERSON")], gold_complete=True)
        assert (a.tp, a.fp, a.fn) == (0, 1, 1)

    def test_matching_is_one_to_one(self):
        """Two predictions overlapping one gold span cannot both score."""
        a = align([gold(0, 10)], [pred(0, 5), pred(5, 10)], gold_complete=True)
        assert a.tp == 1 and a.fp == 1

    def test_greedy_prefers_the_larger_overlap(self):
        a = align([gold(0, 10)], [pred(8, 12), pred(0, 9)], gold_complete=True)
        assert a.matches[0].pred.start == 0

    def test_partial_coverage_is_flagged(self):
        """Part of the identifier survived: a leak, not a boundary nitpick."""
        a = align([gold(0, 10)], [pred(0, 6)], gold_complete=True)
        assert a.tp == 1
        assert len(a.partial) == 1

    def test_full_coverage_is_not_partial(self):
        a = align([gold(2, 8)], [pred(0, 10)], gold_complete=True)
        assert a.partial == []

    def test_adjacent_spans_do_not_overlap(self):
        a = align([gold(0, 5)], [pred(5, 10)], gold_complete=True)
        assert a.tp == 0

    def test_result_is_order_independent(self):
        g = [gold(0, 5), gold(10, 15)]
        p = [pred(10, 15), pred(0, 5)]
        assert align(g, p, gold_complete=True).tp == 2


class TestPredictionsFromResult:
    def test_escape_spans_are_dropped(self):
        """Escapes neutralize input literals; they redact nothing."""
        spans = [
            Span(0, 5, "PERSON", "Aris"),
            Span(10, 22, ESCAPE_LABEL, "{{PERSON_1}}"),
        ]
        out = predictions_from_result(FakeResult(spans))
        assert [s.label for s in out] == ["PERSON"]

    def test_escapes_can_be_kept(self):
        spans = [Span(10, 22, ESCAPE_LABEL, "{{PERSON_1}}")]
        assert len(predictions_from_result(FakeResult(spans), drop_escapes=False)) == 1

    def test_identity_and_source_survive(self):
        spans = [Span(0, 5, "PERSON", "Aris", source="roster", identity="p1")]
        out = predictions_from_result(FakeResult(spans))
        assert out[0].source == "roster" and out[0].identity == "p1"


class TestCounts:
    def test_prf_arithmetic(self):
        p, r, f = prf(tp=8, fp=2, fn=2)
        assert p == pytest.approx(0.8) and r == pytest.approx(0.8) and f == pytest.approx(0.8)

    def test_nothing_measured_is_a_distinct_state_from_a_perfect_score(self):
        """The vacuous 1.0 is what pinned the old baseline at a ceiling."""
        assert not Counts().defined
        assert Counts(tp=1).defined

    def test_no_false_positives_is_genuine_precision(self):
        assert Counts(tp=3).precision == 1.0

    def test_per_label_counts_split_correctly(self):
        a = align(
            [gold(0, 5, "EMAIL"), gold(10, 15, "PERSON")],
            [pred(0, 5, "EMAIL"), pred(20, 25, "PHONE")],
            gold_complete=True,
        )
        by_label = counts_by_label(a)
        assert by_label["EMAIL"].tp == 1
        assert by_label["PHONE"].fp == 1
        assert by_label["PERSON"].fn == 1

    def test_wildcard_gold_is_credited_to_the_predicted_label(self):
        a = align(
            [gold(0, 5, WILDCARD_LABEL)], [pred(0, 5, "CUSTOM_ID")], gold_complete=True
        )
        assert counts_by_label(a)["CUSTOM_ID"].tp == 1

    def test_merge_counts_sums_across_documents(self):
        merged = merge_counts([
            {"EMAIL": Counts(tp=2, fp=1)},
            {"EMAIL": Counts(tp=3, fn=1), "PHONE": Counts(tp=1)},
        ])
        assert merged["EMAIL"] == Counts(tp=5, fp=1, fn=1, unverified=0)
        assert merged["PHONE"].tp == 1


class TestBoundary:
    def test_all_exact(self):
        a = align([gold(0, 5)], [pred(0, 5)], gold_complete=True)
        assert boundary_exact_rate(a.matches) == 1.0

    def test_drift_is_visible(self):
        a = align([gold(0, 5), gold(10, 15)], [pred(0, 5), pred(9, 15)], gold_complete=True)
        assert boundary_exact_rate(a.matches) == 0.5


class TestClusterMetrics:
    def test_correct_merge_scores_clean(self):
        a = align(
            [gold(0, 5, text="Kone", entity="e1"), gold(10, 20, text="Ayodele Kone", entity="e1")],
            [pred(0, 5, text="Kone", identity="p1"), pred(10, 20, text="Ayodele Kone", identity="p1")],
            gold_complete=True,
        )
        assert cluster_metrics(a.matches).ok

    def test_wrong_merge_is_caught(self):
        """Two distinct people collapsed onto one placeholder."""
        a = align(
            [gold(0, 5, text="Priya", entity="e1"), gold(10, 15, text="Rahul", entity="e2")],
            [pred(0, 5, text="Priya", identity="same"), pred(10, 15, text="Rahul", identity="same")],
            gold_complete=True,
        )
        score = cluster_metrics(a.matches)
        assert score.wrong_merges and not score.ok

    def test_missed_merge_is_caught(self):
        a = align(
            [gold(0, 5, text="Kone", entity="e1"), gold(10, 20, text="Ayodele Kone", entity="e1")],
            [pred(0, 5, text="Kone", identity="p1"), pred(10, 20, text="Ayodele Kone", identity="p2")],
            gold_complete=True,
        )
        score = cluster_metrics(a.matches)
        assert score.missed_merges and not score.ok

    def test_unclustered_gold_is_ignored(self):
        a = align([gold(0, 5)], [pred(0, 5)], gold_complete=True)
        assert cluster_metrics(a.matches).ok


class TestIntegrity:
    def test_clean_text_has_no_issues(self):
        assert integrity_issues("hello (world)", "hello (world)") == []

    def test_unbalanced_brackets_caught(self):
        assert any("unbalanced" in i for i in integrity_issues("a", "{{PERSON_1}"))

    def test_line_count_change_caught(self):
        assert "line count changed" in integrity_issues("a\nb", "a")

    def test_placeholder_glued_midword_caught(self):
        assert any("glued" in i for i in integrity_issues("x", "{{PERSON_1}}s"))

    def test_doubled_placeholder_caught(self):
        issues = integrity_issues("x", "{{PERSON_1}} {{PERSON_1}}")
        assert any("twice" in i for i in issues)

    def test_parens_vanishing_with_a_phone_number_is_allowed(self):
        """'+1 (555) 019-2834' -> '{{PHONE_1}}' removes a balanced pair."""
        assert integrity_issues("call +1 (555) 019-2834 now", "call {{PHONE_1}} now") == []


class TestJsonBlocks:
    def test_no_json_returns_none(self):
        valid, errors = json_blocks_are_valid("just prose")
        assert valid is None and errors == []

    def test_placeholder_braces_do_not_open_a_block(self):
        assert extract_json_blocks("hi {{PERSON_1}} there") == []

    def test_valid_redacted_json_parses(self):
        valid, errors = json_blocks_are_valid('{"user": {{PERSON_1}}, "n": 3}')
        assert valid is True and errors == []

    def test_broken_json_is_reported(self):
        valid, errors = json_blocks_are_valid('{"user": , "n": }')
        assert valid is False and errors


class TestCheckAssertions:
    def test_byte_identical_violation_reported(self):
        from tools.scoring import check_assertions

        result = FakeResult([], sanitized="changed")
        violations = check_assertions(
            result, [], {"byte_identical": True, "_source": "original"}
        )
        assert violations

    def test_escaped_literal_violation_reported(self):
        from tools.scoring import check_assertions

        result = FakeResult([], sanitized="x", escapes={})
        violations = check_assertions(
            result, [], {"expect_escaped_literals": ["{{PERSON_1}}"]}
        )
        assert violations
