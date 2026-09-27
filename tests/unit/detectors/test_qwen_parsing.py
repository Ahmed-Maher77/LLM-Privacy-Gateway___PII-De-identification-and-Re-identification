"""Qwen response parsing and grounding.

No Ollama and no model: every case here is a recorded or synthesised response
shape. The parser's contract is that it never raises on model *content* -- only
on a response containing no locatable JSON at all.
"""

from __future__ import annotations

import contextlib
import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from privacy_gateway.detectors.qwen_detector import (
    QwenCandidate,
    QwenParseError,
    ground_candidates,
    parse_qwen_response,
    split_for_context,
)

DOC = "Rania Fahmy runs FleetCore for BrightPath Logistics in Dubai."

VALID = json.dumps(
    [
        {"text": "Rania Fahmy", "entity_type": "PERSON"},
        {"text": "FleetCore", "entity_type": "INTERNAL_SYSTEM"},
    ]
)


def types(result):
    return {(c.entity_type, c.text) for c in result.candidates}


# -- well-formed shapes ------------------------------------------------------

def test_parses_a_plain_json_array():
    assert types(parse_qwen_response(VALID)) == {
        ("PERSON", "Rania Fahmy"),
        ("INTERNAL_SYSTEM", "FleetCore"),
    }


def test_parses_an_object_with_an_entities_key():
    raw = json.dumps({"entities": [{"text": "FleetCore", "entity_type": "INTERNAL_SYSTEM"}]})
    assert types(parse_qwen_response(raw)) == {("INTERNAL_SYSTEM", "FleetCore")}


def test_parses_a_markdown_fenced_array():
    assert len(parse_qwen_response(f"```json\n{VALID}\n```").candidates) == 2


def test_parses_an_unlabelled_fence():
    assert len(parse_qwen_response(f"```\n{VALID}\n```").candidates) == 2


def test_parses_through_a_prose_preamble():
    raw = f"Here are the entities I found:\n\n{VALID}"
    assert len(parse_qwen_response(raw).candidates) == 2


def test_parses_through_a_trailing_explanation():
    raw = f"{VALID}\n\nI identified two entities above."
    assert len(parse_qwen_response(raw).candidates) == 2


def test_strips_a_thinking_block():
    raw = f"<think>Let me look for names...</think>\n{VALID}"
    assert len(parse_qwen_response(raw).candidates) == 2


def test_accepts_the_type_alias_key():
    raw = json.dumps([{"text": "FleetCore", "type": "INTERNAL_SYSTEM"}])
    assert types(parse_qwen_response(raw)) == {("INTERNAL_SYSTEM", "FleetCore")}


def test_empty_array_yields_no_candidates():
    assert parse_qwen_response("[]").candidates == ()


def test_empty_response_yields_no_candidates():
    assert parse_qwen_response("").candidates == ()


def test_whitespace_only_response_yields_no_candidates():
    assert parse_qwen_response("   \n\t ").candidates == ()


# -- malformed content is dropped, not fatal ---------------------------------

def test_truncated_json_raises_parse_error():
    with pytest.raises(QwenParseError):
        parse_qwen_response('[{"text": "Rania Fahmy", "entity_ty')


def test_prose_only_response_raises_parse_error():
    with pytest.raises(QwenParseError):
        parse_qwen_response("I could not find any entities in this document.")


def test_entity_missing_text_is_dropped():
    result = parse_qwen_response(json.dumps([{"entity_type": "PERSON"}]))
    assert result.candidates == ()
    assert result.reasons["missing_text"] == 1


def test_entity_missing_type_is_dropped():
    result = parse_qwen_response(json.dumps([{"text": "Rania Fahmy"}]))
    assert result.reasons["missing_type"] == 1


def test_entity_with_a_non_string_text_is_dropped():
    result = parse_qwen_response(json.dumps([{"text": 42, "entity_type": "PERSON"}]))
    assert result.reasons["missing_text"] == 1


def test_a_bare_string_element_is_dropped():
    result = parse_qwen_response(json.dumps(["Rania Fahmy"]))
    assert result.reasons["not_an_object"] == 1


def test_unknown_entity_type_is_dropped():
    result = parse_qwen_response(json.dumps([{"text": "x", "entity_type": "FAVOURITE_COLOUR"}]))
    assert result.candidates == ()
    assert result.reasons["unknown_type"] == 1


def test_a_type_outside_the_allowed_taxonomy_is_dropped():
    # EMAIL is a real type, but the semantic layer is not trusted with it --
    # the deterministic layer owns structured identifiers.
    result = parse_qwen_response(json.dumps([{"text": "a@b.com", "entity_type": "EMAIL"}]))
    assert result.candidates == ()


def test_duplicates_are_collapsed():
    raw = json.dumps(
        [
            {"text": "FleetCore", "entity_type": "INTERNAL_SYSTEM"},
            {"text": "FleetCore", "entity_type": "INTERNAL_SYSTEM"},
        ]
    )
    result = parse_qwen_response(raw)
    assert len(result.candidates) == 1
    assert result.reasons["duplicate"] == 1


def test_valid_entities_survive_alongside_invalid_ones():
    raw = json.dumps(
        [
            {"text": "Rania Fahmy", "entity_type": "PERSON"},
            {"entity_type": "PERSON"},
            {"text": "x", "entity_type": "NOPE"},
        ]
    )
    result = parse_qwen_response(raw)
    assert types(result) == {("PERSON", "Rania Fahmy")}
    assert result.dropped == 2


@pytest.mark.property
@settings(max_examples=300, deadline=None)
@given(st.text(max_size=200))
def test_parser_never_raises_anything_but_its_own_error(raw):
    with contextlib.suppress(QwenParseError):
        parse_qwen_response(raw)


# -- grounding: offsets come from the document, never from the model ---------

def _ground(candidates, text=DOC, **kw):
    return ground_candidates(candidates, text, priority=30, **kw)


def test_grounding_locates_a_candidate_exactly():
    found, _ = _ground([QwenCandidate("FleetCore", "INTERNAL_SYSTEM")])
    assert len(found) == 1
    assert DOC[found[0].start : found[0].end] == "FleetCore"


def test_every_grounded_entity_slices_back_to_its_own_text():
    found, _ = _ground(
        [QwenCandidate("Rania Fahmy", "PERSON"), QwenCandidate("Dubai", "LOCATION")]
    )
    assert found
    for e in found:
        assert DOC[e.start : e.end] == e.text


def test_a_hallucinated_string_is_dropped_as_ungrounded():
    # The single most important property of this layer: a model that invents
    # an entity produces nothing, rather than a corrupt span.
    found, stats = _ground([QwenCandidate("Sarah Mitchell", "PERSON")])
    assert found == ()
    assert stats["ungrounded"] == 1


def test_grounding_respects_word_boundaries():
    found, stats = _ground([QwenCandidate("Fleet", "INTERNAL_SYSTEM")])
    assert found == ()
    assert stats["ungrounded"] == 1


def test_every_occurrence_is_grounded():
    text = "FleetCore and FleetCore again."
    found, _ = ground_candidates(
        [QwenCandidate("FleetCore", "INTERNAL_SYSTEM")], text, priority=30
    )
    assert len(found) == 2


def test_a_span_covering_most_of_the_document_is_rejected():
    # A model asked for entities sometimes returns a paraphrase of a whole
    # paragraph. On a document long enough for the proportional guard to bite,
    # that must be rejected rather than pseudonymized as one giant "entity".
    long_doc = (DOC + " ") * 40
    sentence = long_doc[: int(len(long_doc) * 0.5)].strip()
    found, stats = ground_candidates(
        [QwenCandidate(sentence, "CONFIDENTIAL_BUSINESS_INFORMATION")],
        long_doc,
        priority=30,
    )
    assert found == ()
    assert stats["too_long"] == 1


def test_an_ordinary_entity_is_not_rejected_on_a_short_document():
    # The proportional guard is floored, so a 9-character system name in a
    # 61-character document is still grounded.
    found, _ = _ground([QwenCandidate("FleetCore", "INTERNAL_SYSTEM")])
    assert len(found) == 1


def test_a_one_character_candidate_is_rejected():
    found, stats = _ground([QwenCandidate("N", "PERSON")])
    assert found == ()
    assert stats["too_short"] == 1


def test_entity_count_is_capped():
    text = " ".join(["Alpha"] * 50)
    found, stats = ground_candidates(
        [QwenCandidate("Alpha", "PERSON")], text, priority=30, max_entities=10
    )
    assert len(found) == 10
    assert stats["capped"] == 1


def test_candidates_for_a_different_document_all_drop():
    found, stats = ground_candidates(
        [QwenCandidate("Rania Fahmy", "PERSON"), QwenCandidate("FleetCore", "INTERNAL_SYSTEM")],
        "An unrelated document about logistics.",
        priority=30,
    )
    assert found == ()
    assert stats["ungrounded"] == 2


def test_grounded_entities_carry_the_qwen_detector_and_priority():
    found, _ = _ground([QwenCandidate("Dubai", "LOCATION")])
    assert found[0].detector == "qwen"
    assert found[0].priority == 30


# -- windowing ---------------------------------------------------------------

def test_short_text_is_a_single_window():
    assert split_for_context(DOC, 4000) == [(0, DOC)]


def test_empty_text_produces_no_windows():
    assert split_for_context("", 4000) == []


def test_long_text_is_split_with_absolute_offsets():
    text = "\n".join(f"line {i}" for i in range(500))
    windows = split_for_context(text, 200)
    assert len(windows) > 1
    for offset, chunk in windows:
        assert text[offset : offset + len(chunk)] == chunk


def test_windows_cover_the_whole_document():
    text = "\n".join(f"line {i}" for i in range(200))
    rebuilt = "".join(chunk for _, chunk in split_for_context(text, 150))
    assert rebuilt == text
