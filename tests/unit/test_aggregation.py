"""Entity aggregation and deterministic overlap resolution.

The property test at the end is the one that matters most: whatever candidates
go in, what comes out is pairwise disjoint, word-aligned and agrees with the
source text. That is what makes the prototype's corruption structurally
impossible rather than merely absent.
"""

from __future__ import annotations

import random

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from privacy_gateway.aggregation.aggregator import (
    AggregationConfig,
    EntityAggregator,
)
from privacy_gateway.entities.entity import DetectedEntity
from privacy_gateway.entities.spans import is_word_aligned
from privacy_gateway.errors import AggregationInvariantError

TEXT = "Rania Fahmy emailed sarah@example.com about FleetCore in Dubai Internet City."
AGG = EntityAggregator()


def ent(start, end, etype="PERSON", detector="ner", conf=0.9, priority=40, source=""):
    return DetectedEntity(
        entity_type=etype,
        text=TEXT[start:end],
        start=start,
        end=end,
        confidence=conf,
        detector=detector,
        priority=priority,
        source=source,
    )


def spans(result):
    return [(e.start, e.end) for e in result.entities]


# -- stage A: cleaning -------------------------------------------------------

def test_a_valid_entity_survives():
    assert spans(AGG.aggregate([ent(0, 11)], TEXT)) == [(0, 11)]


def test_an_out_of_range_span_is_rejected():
    bad = DetectedEntity(
        entity_type="PERSON", text="xx", start=len(TEXT) + 5, end=len(TEXT) + 7,
        confidence=0.9, detector="qwen",
    )
    result = AGG.aggregate([bad], TEXT)
    assert result.entities == ()
    assert result.rejected[0].verdict == "out_of_range"


def test_a_text_mismatch_is_rejected():
    bad = DetectedEntity(
        entity_type="PERSON", text="Ahmed Farid", start=0, end=11,
        confidence=0.9, detector="qwen",
    )
    assert AGG.aggregate([bad], TEXT).entities == ()


def test_a_subword_fragment_from_an_expanding_detector_is_widened():
    # "Ran" from the NER layer becomes "Rania", not a fragment and not a drop.
    result = AGG.aggregate([ent(0, 3, detector="ner")], TEXT)
    assert [e.text for e in result.entities] == ["Rania"]


def test_a_subword_fragment_from_a_non_expanding_detector_is_dropped():
    result = AGG.aggregate([ent(0, 3, detector="domain", priority=80)], TEXT)
    assert result.entities == ()
    assert result.rejected[0].verdict == "not_word_aligned"


def test_a_single_character_person_is_dropped():
    # The literal <PER_2> bug: "N" of "Rania" must never survive as an entity.
    result = AGG.aggregate([ent(0, 1, detector="ner", conf=0.99)], TEXT)
    assert all(e.text != "N" for e in result.entities)


def test_markdown_wrappers_are_trimmed():
    text = "we use **FleetCore** daily"
    e = DetectedEntity(
        entity_type="INTERNAL_SYSTEM", text="**FleetCore**", start=7, end=20,
        confidence=0.95, detector="domain", priority=80,
    )
    assert [x.text for x in AGG.aggregate([e], text).entities] == ["FleetCore"]


def test_a_possessive_is_stripped():
    text = "Sarah's laptop"
    e = DetectedEntity(
        entity_type="PERSON", text="Sarah's", start=0, end=7,
        confidence=0.9, detector="ner",
    )
    assert [x.text for x in AGG.aggregate([e], text).entities] == ["Sarah"]


def test_asr_filler_from_a_statistical_detector_is_dropped():
    text = "Mhm. Okay."
    e = DetectedEntity(
        entity_type="PERSON", text="Mhm", start=0, end=3, confidence=0.95, detector="ner"
    )
    assert AGG.aggregate([e], text).entities == ()


def test_a_lowercase_common_noun_from_a_statistical_detector_is_dropped():
    text = "our operations team"
    e = DetectedEntity(
        entity_type="ORGANIZATION", text="operations", start=4, end=14,
        confidence=0.9, detector="ner",
    )
    result = AGG.aggregate([e], text)
    assert result.entities == ()
    assert result.rejected[0].verdict == "not_proper_noun"


def test_a_capitalised_common_word_from_a_statistical_detector_is_dropped():
    text = "Operations are fine"
    e = DetectedEntity(
        entity_type="ORGANIZATION", text="Operations", start=0, end=10,
        confidence=0.9, detector="presidio", priority=60,
    )
    assert AGG.aggregate([e], text).rejected[0].verdict == "common_word"


def test_a_curated_detector_is_exempt_from_the_common_word_filter():
    # A company genuinely called "Content" is still protected via the lexicon.
    text = "Content ships tomorrow"
    e = DetectedEntity(
        entity_type="ORGANIZATION", text="Content", start=0, end=7,
        confidence=0.95, detector="domain", priority=80,
    )
    assert [x.text for x in AGG.aggregate([e], text).entities] == ["Content"]


def test_a_low_confidence_candidate_is_dropped():
    assert AGG.aggregate([ent(0, 11, conf=0.05)], TEXT).entities == ()


# -- stage B: duplicate merging ---------------------------------------------

def test_identical_spans_from_two_detectors_merge():
    result = AGG.aggregate(
        [ent(0, 11, detector="ner", priority=40), ent(0, 11, detector="registry", priority=100)],
        TEXT,
    )
    assert len(result.entities) == 1


def test_the_merged_entity_keeps_the_higher_priority_detector():
    result = AGG.aggregate(
        [ent(0, 11, detector="ner", priority=40), ent(0, 11, detector="registry", priority=100)],
        TEXT,
    )
    assert result.entities[0].detector == "registry"


def test_corroboration_raises_confidence_but_is_capped():
    result = AGG.aggregate(
        [
            ent(0, 11, detector="ner", conf=0.90, priority=40),
            ent(0, 11, detector="registry", conf=0.90, priority=100),
        ],
        TEXT,
    )
    assert 0.90 < result.entities[0].confidence <= 0.99


def test_the_merged_entity_records_the_other_detectors():
    result = AGG.aggregate(
        [ent(0, 11, detector="ner", priority=40), ent(0, 11, detector="registry", priority=100)],
        TEXT,
    )
    assert "ner" in result.entities[0].metadata["also_detected_by"]


# -- stage C: overlap resolution --------------------------------------------

def test_a_contained_span_is_absorbed_by_its_container():
    dubai = TEXT.index("Dubai")
    whole = (dubai, dubai + len("Dubai Internet City"))
    result = AGG.aggregate(
        [ent(*whole, etype="LOCATION"), ent(dubai, dubai + 5, etype="LOCATION")], TEXT
    )
    assert spans(result) == [whole]


def test_a_higher_priority_inner_span_beats_a_sloppy_container():
    # A regex EMAIL nested inside an NER ORGANIZATION must not be swallowed.
    start = TEXT.index("sarah@example.com")
    outer = ent(start - 8, start + 17, etype="ORGANIZATION", detector="ner", priority=40)
    inner = ent(start, start + 17, etype="EMAIL", detector="regex", priority=90, conf=0.99)
    result = AGG.aggregate([outer, inner], TEXT)
    assert [e.entity_type for e in result.entities] == ["EMAIL"]


def test_a_partial_overlap_keeps_the_higher_priority_candidate():
    a = ent(0, 11, detector="ner", priority=40)
    b = ent(6, 19, detector="registry", priority=100)
    result = AGG.aggregate([a, b], TEXT)
    assert result.entities[0].detector == "registry"


def test_an_overlap_loser_is_dropped_entirely_not_trimmed():
    # Trimming a loser to its non-overlapping remainder is how a fragment gets
    # manufactured from the other direction.
    a = ent(0, 11, detector="ner", priority=40)
    b = ent(6, 19, detector="registry", priority=100)
    result = AGG.aggregate([a, b], TEXT)
    assert len(result.entities) == 1
    assert result.entities[0].span == (6, 19)


def test_output_is_always_sorted_by_start():
    result = AGG.aggregate([ent(44, 53, etype="ORGANIZATION"), ent(0, 11)], TEXT)
    assert spans(result) == sorted(spans(result))


def test_output_is_pairwise_disjoint():
    result = AGG.aggregate(
        [ent(0, 11), ent(0, 5), ent(6, 11), ent(0, 19, etype="ORGANIZATION")], TEXT
    )
    for a, b in zip(result.entities, result.entities[1:], strict=False):
        assert a.end <= b.start


def test_resolution_is_independent_of_input_order():
    candidates = [
        ent(0, 11, detector="ner", priority=40),
        ent(0, 5, detector="presidio", priority=60),
        ent(6, 19, detector="registry", priority=100),
        ent(44, 53, etype="ORGANIZATION", detector="domain", priority=80),
    ]
    reference = spans(AGG.aggregate(candidates, TEXT))
    rng = random.Random(0)
    for _ in range(50):
        shuffled = candidates[:]
        rng.shuffle(shuffled)
        assert spans(AGG.aggregate(shuffled, TEXT)) == reference


def test_empty_input_returns_empty():
    assert AGG.aggregate([], TEXT).entities == ()


def test_stats_account_for_every_candidate():
    result = AGG.aggregate([ent(0, 11), ent(0, 5), ent(0, 1)], TEXT)
    assert result.stats["candidates_in"] == 3


# -- post-conditions ---------------------------------------------------------

def test_post_conditions_detect_a_broken_resolver(monkeypatch):
    # A guard on the guard: if the sweep ever returned overlapping spans, the
    # invariant check must fail loudly rather than corrupting the document.
    agg = EntityAggregator()
    monkeypatch.setattr(
        agg, "_resolve", lambda entities: ([ent(0, 11), ent(6, 19)], [])
    )
    with pytest.raises(AggregationInvariantError):
        agg.aggregate([ent(0, 11)], TEXT)


def test_word_boundary_can_be_disabled_by_configuration():
    agg = EntityAggregator(AggregationConfig(require_word_boundary=False, min_person_chars=1))
    result = agg.aggregate([ent(0, 3, detector="domain", priority=80)], TEXT)
    assert [e.text for e in result.entities] == ["Ran"]


# -- property ----------------------------------------------------------------

_SAMPLE = "Ahmed Farid met Rania Fahmy and Hossam Badri about FleetCore in Dubai."


@pytest.mark.property
@settings(max_examples=200, deadline=None)
@given(
    st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=len(_SAMPLE) - 1),
            st.integers(min_value=1, max_value=20),
            st.sampled_from(["PERSON", "ORGANIZATION", "LOCATION", "EMAIL"]),
            st.sampled_from(["regex", "registry", "domain", "presidio", "ner", "qwen"]),
            st.floats(min_value=0.3, max_value=1.0, allow_nan=False),
        ),
        max_size=25,
    )
)
def test_property_output_is_always_disjoint_aligned_and_faithful(raw):
    candidates = []
    for start, length, etype, detector, conf in raw:
        end = min(start + length, len(_SAMPLE))
        if end <= start:
            continue
        candidates.append(
            DetectedEntity(
                entity_type=etype,
                text=_SAMPLE[start:end],
                start=start,
                end=end,
                confidence=conf,
                detector=detector,
                priority={"regex": 90, "registry": 100, "domain": 80,
                          "presidio": 60, "ner": 40, "qwen": 30}[detector],
            )
        )
    result = EntityAggregator().aggregate(candidates, _SAMPLE)
    for a, b in zip(result.entities, result.entities[1:], strict=False):
        assert a.end <= b.start
    for e in result.entities:
        assert _SAMPLE[e.start : e.end] == e.text
        assert is_word_aligned(_SAMPLE, e.start, e.end)


# -- DATE length cap ----------------------------------------------------------
#
# DATE defaults to policy ALLOW, so rejecting an oversized candidate costs
# nothing -- but an oversized one left in place can win an overlap against a
# real entity underneath it and then sail through unprotected, since ALLOW
# never replaces it. Presidio's SpacyRecognizer has been observed returning a
# 35-character DATE_TIME span on a single mis-parsed "HH:MM - Name:" line.

def test_an_oversized_date_span_is_rejected():
    text = "09:00 - Ahmed Hassan: Good morning. Sarah Mitchell will lead."
    e = DetectedEntity(
        entity_type="DATE", text=text[:34], start=0, end=34,
        confidence=0.85, detector="presidio",
    )
    result = AGG.aggregate([e], text)
    assert result.entities == ()
    assert result.rejected[0].verdict == "too_long"


def test_an_oversized_date_no_longer_suppresses_the_real_entity_beneath_it():
    text = "09:00 - Ahmed Hassan: Good morning. Sarah Mitchell will lead."
    bogus_date = DetectedEntity(
        entity_type="DATE", text=text[:34], start=0, end=34,
        confidence=0.85, detector="presidio", priority=60,
    )
    real_name = DetectedEntity(
        entity_type="PERSON", text="Ahmed Hassan", start=8, end=20,
        confidence=1.0, detector="ner", priority=40,
    )
    result = AGG.aggregate([bogus_date, real_name], text)
    assert [e.text for e in result.entities] == ["Ahmed Hassan"]


def test_an_ordinary_short_date_is_still_accepted():
    text = "See you tomorrow."
    e = DetectedEntity(
        entity_type="DATE", text="tomorrow", start=8, end=16,
        confidence=0.85, detector="presidio",
    )
    result = AGG.aggregate([e], text)
    assert [x.text for x in result.entities] == ["tomorrow"]


# -- must contain a letter ----------------------------------------------------
#
# Presidio's spaCy-sourced recogniser has also been observed labelling a bare
# bracketed clock time ("10:08:20") as ORGANIZATION on a bracketed-timestamp
# transcript line. A capitalised-type entity with no letters at all is never
# legitimate, regardless of type.

def test_a_bare_timestamp_typed_as_organization_is_rejected():
    text = "seen at 10:08:20 today"
    e = DetectedEntity(
        entity_type="ORGANIZATION", text="10:08:20", start=8, end=16,
        confidence=0.95, detector="presidio",
    )
    result = AGG.aggregate([e], text)
    assert result.entities == ()
    assert result.rejected[0].verdict == "not_proper_noun"


# -- short-span floor split (person vs. everything else) ---------------------

def test_a_three_letter_person_name_at_high_confidence_survives():
    text = "Kim called today."
    e = DetectedEntity(
        entity_type="PERSON", text="Kim", start=0, end=3,
        confidence=0.95, detector="ner",
    )
    result = AGG.aggregate([e], text)
    assert [x.text for x in result.entities] == ["Kim"]


def test_a_three_letter_organization_acronym_needs_higher_confidence():
    # MAC/SSN/CVV/API/PII were all observed at Presidio's flat 0.85
    # spaCy-sourced score, mistagged as ORGANIZATION.
    text = "the MAC address is listed"
    e = DetectedEntity(
        entity_type="ORGANIZATION", text="MAC", start=4, end=7,
        confidence=0.85, detector="presidio",
    )
    result = AGG.aggregate([e], text)
    assert result.entities == ()
    assert result.rejected[0].verdict == "too_short"


def test_a_short_organization_at_high_confidence_still_survives():
    text = "the MAC address is listed"
    e = DetectedEntity(
        entity_type="ORGANIZATION", text="MAC", start=4, end=7,
        confidence=0.95, detector="ner",
    )
    result = AGG.aggregate([e], text)
    assert [x.text for x in result.entities] == ["MAC"]


# -- same-type containment: completeness beats detector priority ------------
#
# NER correctly detects the complete "James Anderson"; Presidio separately
# detects only "Anderson" (a fragment of the same name) at higher detector
# priority. The complete span must win regardless -- priority only arbitrates
# between DIFFERENT entity types nested inside one another (an EMAIL inside a
# sloppy ORGANIZATION), never between two candidates for the same name.

def test_a_complete_name_beats_a_higher_priority_fragment_of_itself():
    text = 'SERVICE_OWNER="James Anderson"'
    start = text.index("James")
    complete = DetectedEntity(
        entity_type="PERSON", text="James Anderson", start=start, end=start + 14,
        confidence=0.98, detector="ner", priority=40,
    )
    fragment = DetectedEntity(
        entity_type="PERSON", text="Anderson", start=start + 6, end=start + 14,
        confidence=0.85, detector="presidio", priority=60,
    )
    result = AGG.aggregate([complete, fragment], text)
    assert [e.text for e in result.entities] == ["James Anderson"]


def test_cross_type_containment_still_prefers_the_higher_priority_inner_span():
    # The EMAIL-inside-ORGANIZATION case must be unaffected by the same-type
    # carve-out above.
    start = TEXT.index("sarah@example.com")
    outer = ent(start - 8, start + 17, etype="ORGANIZATION", detector="ner", priority=40)
    inner = ent(start, start + 17, etype="EMAIL", detector="regex", priority=90, conf=0.99)
    result = AGG.aggregate([outer, inner], TEXT)
    assert [e.entity_type for e in result.entities] == ["EMAIL"]
