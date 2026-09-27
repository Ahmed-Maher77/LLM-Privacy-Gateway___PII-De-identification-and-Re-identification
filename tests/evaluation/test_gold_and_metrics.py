"""The evaluation harness, and the guards that keep its output honest.

The provenance tests exist because "do not fabricate results" has to be
something the build enforces, not something a person remembers. A Qwen figure
cannot be emitted while Qwen is disabled, and a percentile cannot be emitted
from a sample too small to support it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from privacy_gateway.entities.entity import DetectedEntity
from privacy_gateway.evaluation.gold import (
    MIN_INDEPENDENT_FRACTION,
    GoldDocument,
    GoldSet,
    GoldSpan,
    circularity_warning,
)
from privacy_gateway.evaluation.metrics import (
    Counts,
    evaluate_document,
    speaker_label_spans,
    without_speaker_lines,
)
from privacy_gateway.evaluation.report import NOT_MEASURED, render_markdown
from privacy_gateway.evaluation.sweep import SWEEP, dataset_summary, select

GOLD_DIR = Path(__file__).resolve().parents[2] / "evaluation" / "gold"

TEXT = "Ahmed Farid met Rania Fahmy about FleetCore."


def span(start, end, etype="PERSON", **kw):
    return GoldSpan(start=start, end=end, entity_type=etype, text=TEXT[start:end], **kw)


def pred(start, end, etype="PERSON", detector="ner"):
    return DetectedEntity(
        entity_type=etype, text=TEXT[start:end], start=start, end=end,
        confidence=0.9, detector=detector,
    )


def doc(entities=()):
    return GoldDocument(doc_id="d1", text=TEXT, entities=tuple(entities))


# -- counts ------------------------------------------------------------------

def test_perfect_match_scores_one():
    counts = Counts(tp=4, fp=0, fn=0)
    assert counts.precision == 1.0 and counts.recall == 1.0 and counts.f1 == 1.0


def test_no_predictions_gives_no_precision():
    assert Counts(tp=0, fp=0, fn=3).precision is None


def test_f1_is_none_when_either_side_is_none():
    assert Counts().f1 is None


def test_low_support_reports_counts_instead_of_f1():
    out = Counts(tp=1, fp=0, fn=0).to_dict(support=3)
    assert "f1" not in out and "note" in out


def test_sufficient_support_reports_f1():
    assert "f1" in Counts(tp=10, fp=1, fn=1).to_dict(support=20)


# -- strict vs relaxed -------------------------------------------------------

def test_an_exact_match_is_a_strict_true_positive():
    result, _ = evaluate_document(doc([span(0, 11)]), [pred(0, 11)])
    assert result.strict.tp == 1


def test_a_boundary_error_is_a_strict_miss():
    # The whole point of strict matching: "<PER_2>ehal Fahmy" must not score as
    # a near-hit on "Rania Fahmy".
    result, _ = evaluate_document(doc([span(16, 27)]), [pred(17, 27)])
    assert result.strict.tp == 0
    assert result.strict.fp == 1 and result.strict.fn == 1


def test_a_boundary_error_still_counts_under_overlap():
    result, _ = evaluate_document(doc([span(16, 27)]), [pred(17, 27)])
    assert result.overlap_typed.tp == 1


def test_the_strict_overlap_gap_is_the_boundary_error_budget():
    result, _ = evaluate_document(doc([span(16, 27)]), [pred(17, 27)])
    assert result.overlap_typed.tp > result.strict.tp


def test_a_type_error_is_caught_by_the_type_agnostic_view():
    result, _ = evaluate_document(doc([span(0, 11)]), [pred(0, 11, "ORGANIZATION")])
    assert result.strict.tp == 0
    assert result.type_agnostic.tp == 1


# -- privacy-specific figures ------------------------------------------------

def test_a_completely_missed_entity_marks_the_document_as_leaking():
    result, _ = evaluate_document(doc([span(0, 11)]), [])
    assert result.docs_with_any_leak == 1


def test_a_partially_covered_entity_does_not_mark_a_leak():
    result, _ = evaluate_document(doc([span(0, 11)]), [pred(0, 5)])
    assert result.docs_with_any_leak == 0


def test_char_recall_reflects_partial_coverage():
    result, _ = evaluate_document(doc([span(0, 11)]), [pred(0, 5)])
    assert 0 < result.char_recall < 1


def test_char_recall_is_one_for_full_coverage():
    result, _ = evaluate_document(doc([span(0, 11)]), [pred(0, 11)])
    assert result.char_recall == 1.0


# -- excluded types and certainty -------------------------------------------

def test_dates_are_excluded_from_scoring_on_both_sides():
    result, _ = evaluate_document(
        doc([span(0, 11, "DATE")]), [pred(0, 11, "DATE")]
    )
    assert result.strict.tp == 0 and result.strict.fp == 0 and result.strict.fn == 0


def test_ambiguous_spans_are_excluded_from_both_numerator_and_denominator():
    d = doc([span(0, 11, certainty="ambiguous")])
    result, _ = evaluate_document(d, [])
    assert result.strict.fn == 0


def test_ambiguous_spans_are_counted_separately():
    gold = GoldSet((doc([span(0, 11, certainty="ambiguous"), span(16, 27)]),))
    assert gold.scored_span_count == 1
    assert gold.excluded_span_count == 1


# -- errors carry context ----------------------------------------------------

def test_a_false_negative_carries_surrounding_context():
    result, _ = evaluate_document(doc([span(0, 11)]), [])
    assert "»" in result.false_negatives[0].context


def test_a_false_positive_names_its_detector():
    result, _ = evaluate_document(doc([]), [pred(0, 11, detector="presidio")])
    assert result.false_positives[0].detectors == ("presidio",)


# -- speaker lines -----------------------------------------------------------

TRANSCRIPT = "Ahmed Farid   0:31 \nSaid hello to Rania Fahmy.\n"


def test_speaker_label_lines_are_located():
    assert len(speaker_label_spans(TRANSCRIPT)) == 1


def test_removing_speaker_lines_drops_spans_on_them():
    d = GoldDocument(
        doc_id="t",
        text=TRANSCRIPT,
        entities=(
            GoldSpan(0, 11, "PERSON", "Ahmed Farid"),
            GoldSpan(
                TRANSCRIPT.index("Rania Fahmy"),
                TRANSCRIPT.index("Rania Fahmy") + 11,
                "PERSON",
                "Rania Fahmy",
            ),
        ),
    )
    filtered, _ = without_speaker_lines(GoldSet((d,)), {})
    assert len(filtered.documents[0].entities) == 1


# -- gold set validation -----------------------------------------------------

def test_a_span_disagreeing_with_its_text_is_invalid():
    bad = GoldDocument(
        doc_id="d", text=TEXT, entities=(GoldSpan(0, 11, "PERSON", "Wrong Name"),)
    )
    assert bad.validate()


def test_an_out_of_range_span_is_invalid():
    bad = GoldDocument(doc_id="d", text=TEXT, entities=(GoldSpan(0, 999, "PERSON", "x"),))
    assert bad.validate()


def test_overlapping_gold_spans_are_invalid():
    bad = GoldDocument(
        doc_id="d",
        text=TEXT,
        entities=(span(0, 11), span(5, 15)),
    )
    assert any("overlap" in p for p in bad.validate())


def test_duplicate_doc_ids_are_invalid():
    assert any("duplicate" in p for p in GoldSet((doc(), doc())).validate())


def test_a_valid_document_has_no_problems():
    assert doc([span(0, 11)]).validate() == []


# -- circularity guard -------------------------------------------------------

def test_an_all_accepted_gold_set_triggers_the_circularity_warning():
    entities = tuple(
        span(0, 11, provenance="accepted_candidate") for _ in range(1)
    )
    gold = GoldSet((GoldDocument(doc_id="d", text=TEXT, entities=entities),))
    assert circularity_warning(gold) is not None


def test_an_independently_labelled_set_does_not_trigger_it():
    gold = GoldSet((doc([span(0, 11, provenance="independent")]),))
    assert circularity_warning(gold) is None


def test_the_floor_is_documented():
    assert 0 < MIN_INDEPENDENT_FRACTION < 1


# -- the shipped gold set ----------------------------------------------------

@pytest.fixture(scope="module")
def shipped():
    gold = GoldSet.load(GOLD_DIR)
    return GoldSet(tuple(d for d in gold if d.labeler), gold.path)


def test_the_shipped_gold_set_is_valid(shipped):
    assert shipped.validate() == []


def test_the_shipped_gold_set_is_large_enough_to_compare_configurations(shipped):
    assert shipped.scored_span_count >= 150


def test_every_shipped_span_slices_back_to_its_own_text(shipped):
    for document in shipped:
        for entity in document.entities:
            assert document.text[entity.start : entity.end] == entity.text


def test_the_shipped_gold_set_clears_the_circularity_floor(shipped):
    assert shipped.independent_fraction() >= MIN_INDEPENDENT_FRACTION


def test_the_shipped_gold_set_records_who_labelled_it(shipped):
    # The labeller is an AI assistant, and that must be stated on every record
    # rather than implied.
    for document in shipped:
        assert "not human-verified" in document.labeler


def test_the_dataset_summary_states_the_labelling_caveat(shipped):
    summary = dataset_summary(shipped)
    assert summary["inter_annotator_agreement"] is None
    assert "not human-verified" in summary["labeling_note"].lower() or (
        "NOT by a human" in summary["labeling_note"]
    )


def test_dev_and_test_splits_are_both_populated(shipped):
    splits = {d.split for d in shipped}
    assert splits == {"dev", "test"}


# -- the report renderer -----------------------------------------------------

def _payload(**overrides):
    base = {
        "provenance": {"git_commit": "abc123", "git_dirty": False, "platform": "test"},
        "dataset": {
            "documents": 5,
            "entities_scored": 40,
            "entities_excluded_ambiguous": 2,
            "independent_fraction": 0.9,
            "per_type_counts": {"PERSON": 30, "PHONE": 2},
        },
        "configs": [],
        "excluding_speaker_lines": {},
    }
    base.update(overrides)
    return base


def test_a_skipped_config_renders_its_reason_not_a_zero():
    markdown = render_markdown(
        _payload(
            configs=[
                {
                    "key": "C",
                    "label": "Qwen only",
                    "status": "skipped",
                    "detectors": ["qwen"],
                    "reason": "qwen disabled",
                    "metrics": None,
                }
            ]
        )
    )
    assert "skipped: qwen disabled" in markdown
    assert NOT_MEASURED in markdown
    assert "| 0.000 |" not in markdown


def test_a_low_support_type_renders_as_counts_only():
    assert "too few for F1" in render_markdown(_payload())


def test_the_labelling_caveat_precedes_the_numbers():
    markdown = render_markdown(_payload())
    assert markdown.index("not** by a human") < markdown.index("## Configurations")


def test_a_dirty_working_tree_is_shown():
    payload = _payload()
    payload["provenance"]["git_dirty"] = True
    assert "dirty" in render_markdown(payload)


# -- sweep configuration -----------------------------------------------------

def test_the_brief_configurations_are_all_present():
    assert {"A", "B", "C", "D", "E", "F", "G"} <= set(SWEEP)


def test_selecting_a_subset_works():
    assert [c.key for c in select("A,E")] == ["A", "E"]


def test_selecting_nothing_returns_every_configuration():
    assert len(select(None)) == len(SWEEP)


def test_an_unknown_configuration_key_is_ignored():
    assert select("A,ZZZ") == [SWEEP["A"]]
