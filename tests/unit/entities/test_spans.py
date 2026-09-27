"""Span validation and repair.

Several cases below are lifted verbatim from the prototype's corrupted output
in tests/regression/fixtures/prototype_v0/.
"""

from __future__ import annotations

import pytest

from privacy_gateway.entities.entity import DetectedEntity
from privacy_gateway.entities.spans import (
    SpanVerdict,
    expand_to_word_boundary,
    is_asr_noise,
    is_word_aligned,
    realign,
    strip_possessive,
    trim_span,
    validate_span,
)

TEXT = "Rania Fahmy and Hossam Badri met Lamia Aly.\nNice. `a@b.com` **FleetCore**"


def ent(start, end, text=None, etype="PERSON", detector="ner", conf=0.9):
    return DetectedEntity(
        entity_type=etype, text=text if text is not None else TEXT[start:end],
        start=start, end=end, confidence=conf, detector=detector,
    )


# -- is_word_aligned ---------------------------------------------------------

@pytest.mark.parametrize(
    "start,end,expected",
    [
        (0, 11, True),    # "Rania Fahmy"
        (0, 1, False),    # "N"  -> the <PER_2>ehal Fahmy bug
        (0, 3, False),    # "Neh"
        (16, 19, False),  # "She" -> the <PER_13>rif Badri bug
        (16, 22, True),   # "Hossam"
        (39, 41, False),  # "Al"  -> the <PER_23>y bug
        (39, 42, True),   # "Aly"
    ],
)
def test_word_alignment_detects_midword_edges(start, end, expected):
    assert is_word_aligned(TEXT, start, end) is expected


def test_span_at_document_start_is_left_aligned():
    assert is_word_aligned("Ahmed", 0, 5)


def test_span_at_document_end_is_right_aligned():
    assert is_word_aligned("Ahmed", 0, 5)


def test_span_bounded_by_punctuation_is_aligned():
    assert is_word_aligned("Hi, Ahmed.", 4, 9)


def test_zero_length_span_is_not_aligned():
    assert not is_word_aligned(TEXT, 5, 5)


def test_out_of_range_span_is_not_aligned():
    assert not is_word_aligned(TEXT, 0, len(TEXT) + 5)


# -- expansion ---------------------------------------------------------------

@pytest.mark.parametrize(
    "start,end,want",
    [
        (0, 1, "Rania"),       # "N"   fragment
        (16, 19, "Hossam"),    # "She" fragment
        (39, 41, "Aly"),       # "Al"  fragment
        (0, 11, "Rania Fahmy"),  # already aligned, unchanged
    ],
)
def test_expansion_recovers_the_whole_word(start, end, want):
    s, e = expand_to_word_boundary(TEXT, start, end)
    assert TEXT[s:e] == want


def test_expansion_is_idempotent():
    once = expand_to_word_boundary(TEXT, 0, 1)
    assert expand_to_word_boundary(TEXT, *once) == once


# -- trimming ----------------------------------------------------------------

def test_trim_removes_leading_backtick():
    # EMAIL_PATTERN's character class includes a backtick, so every match in
    # the SME transcript starts one character early.
    text = "`michael.brown@example.com`"
    s, e = trim_span(text, 0, len(text) - 1)
    assert text[s:e] == "michael.brown@example.com"


def test_trim_removes_markdown_emphasis():
    text = "**FleetCore**"
    s, e = trim_span(text, 0, len(text))
    assert text[s:e] == "FleetCore"


def test_trim_removes_trailing_comma():
    text = "Ahmed,"
    s, e = trim_span(text, 0, len(text))
    assert text[s:e] == "Ahmed"


def test_trim_of_all_wrapper_characters_collapses():
    text = "***"
    s, e = trim_span(text, 0, 3)
    assert e <= s


def test_strip_possessive():
    text = "Sarah's laptop"
    s, e = strip_possessive(text, 0, 7)
    assert text[s:e] == "Sarah"


def test_strip_possessive_leaves_a_plain_name():
    assert strip_possessive("Sarah", 0, 5) == (0, 5)


# -- validate_span -----------------------------------------------------------

def test_valid_span_passes():
    assert validate_span(ent(0, 11), TEXT) is SpanVerdict.VALID


def test_out_of_range_span_is_rejected():
    e = DetectedEntity(
        entity_type="PERSON", text="xx", start=len(TEXT) + 1, end=len(TEXT) + 3,
        confidence=0.9, detector="qwen",
    )
    assert validate_span(e, TEXT) is SpanVerdict.OUT_OF_RANGE


def test_text_mismatch_is_rejected():
    e = DetectedEntity(
        entity_type="PERSON", text="Ahmed Farid", start=0, end=11,
        confidence=0.9, detector="qwen",
    )
    assert validate_span(e, TEXT) is SpanVerdict.TEXT_MISMATCH


def test_midword_span_is_flagged_not_word_aligned():
    assert validate_span(ent(0, 3), TEXT) is SpanVerdict.NOT_WORD_ALIGNED


def test_single_character_span_is_too_short():
    assert validate_span(ent(0, 1), TEXT) is SpanVerdict.TOO_SHORT


def test_overlong_span_is_rejected():
    assert validate_span(ent(0, 60), TEXT, max_chars=20) is SpanVerdict.TOO_LONG


def test_person_span_crossing_a_newline_is_rejected():
    idx = TEXT.index("\n")
    assert validate_span(ent(33, idx + 5), TEXT) is SpanVerdict.CROSSES_NEWLINE


def test_span_with_no_alphanumeric_is_rejected():
    text = "-- ,. --"
    e = DetectedEntity(
        entity_type="PERSON", text=" ,. ", start=2, end=6,
        confidence=0.9, detector="ner",
    )
    assert validate_span(e, text) is SpanVerdict.NO_ALNUM


# -- realign -----------------------------------------------------------------

def test_realign_expands_a_fragment_for_an_expanding_detector():
    out = realign(ent(16, 19), TEXT, expand=True)   # "She"
    assert out is not None and out.text == "Hossam"
    assert out.metadata["realigned_from"] == (16, 19)


def test_realign_does_not_expand_when_expansion_is_disabled():
    out = realign(ent(16, 19), TEXT, expand=False)
    assert out is not None and out.text == "She"
    # It stays misaligned, so validate_span will drop it.
    assert validate_span(out, TEXT) is SpanVerdict.NOT_WORD_ALIGNED


def test_realign_trims_a_backticked_email():
    text = "mail me at `a@b.com` ok"
    e = DetectedEntity(
        entity_type="EMAIL", text="`a@b.com", start=11, end=19,
        confidence=0.99, detector="regex",
    )
    out = realign(e, text, expand=False)
    assert out is not None and out.text == "a@b.com"


def test_realign_truncates_a_person_span_at_a_newline():
    idx = TEXT.index("\n")
    e = DetectedEntity(
        entity_type="PERSON", text=TEXT[33 : idx + 5], start=33, end=idx + 5,
        confidence=0.9, detector="ner",
    )
    out = realign(e, TEXT, expand=False)
    assert out is not None and "\n" not in out.text


def test_realign_returns_none_for_an_unsalvageable_span():
    text = "*** ***"
    e = DetectedEntity(
        entity_type="PERSON", text="***", start=0, end=3,
        confidence=0.9, detector="ner",
    )
    assert realign(e, text, expand=False) is None


def test_realigned_entity_text_still_matches_its_span():
    out = realign(ent(16, 19), TEXT, expand=True)
    assert TEXT[out.start : out.end] == out.text


# -- ASR noise ---------------------------------------------------------------

@pytest.mark.parametrize("word", ["Mhm", "mm.", "Ohh", "Yeah", "OK", "so"])
def test_asr_filler_is_recognised(word):
    assert is_asr_noise(word)


@pytest.mark.parametrize("word", ["Rania", "Ahmed", "FleetCore", "Cortana"])
def test_real_names_are_not_asr_filler(word):
    assert not is_asr_noise(word)
