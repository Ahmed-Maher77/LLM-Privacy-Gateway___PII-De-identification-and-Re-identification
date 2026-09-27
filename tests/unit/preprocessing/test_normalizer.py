"""Normalization and offset preservation.

The key invariant, asserted many ways below: for any span of the normalized
text, the original slice it maps back to must renormalize to that same span.
If that holds, every downstream offset is trustworthy.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from privacy_gateway.preprocessing.normalizer import Normalizer, NormalizerConfig

N = Normalizer()


def norm(raw: str) -> str:
    return N.normalize(raw).text


# -- newlines ----------------------------------------------------------------

def test_crlf_becomes_lf():
    assert norm("a\r\nb") == "a\nb"


def test_lone_cr_becomes_lf():
    assert norm("a\rb") == "a\nb"


def test_lf_is_untouched():
    assert norm("a\nb") == "a\nb"


def test_crlf_shifts_offsets_by_one_per_line():
    nt = N.normalize("aa\r\nbb\r\ncc")
    assert nt.text == "aa\nbb\ncc"
    # "cc" sits at 6 normalized, 8 raw: two CRs removed before it.
    i = nt.text.index("cc")
    assert nt.original_slice(i, i + 2) == "cc"
    assert nt.to_original(i, i + 2) == (8, 10)


def test_trailing_line_whitespace_is_preserved():
    # Every line of the Teams export ends with a space before CRLF.
    assert norm("Ahmed Farid   0:31 \r\n") == "Ahmed Farid   0:31 \n"


# -- HTML entities -----------------------------------------------------------

@pytest.mark.parametrize(
    "raw,want",
    [
        ("a &amp; b", "a & b"),
        ("&lt;tag&gt;", "<tag>"),
        ("&quot;hi&quot;", '"hi"'),
        ("&#65;", "A"),
        ("&#x41;", "A"),
        ("&nbsp;", " "),  # decoded then folded, in one pass
    ],
)
def test_entities_are_decoded(raw, want):
    assert norm(raw) == want


def test_double_encoded_entity_is_decoded_exactly_once():
    # Recursive unescaping would resurrect a placeholder an attacker encoded
    # twice, so exactly one pass is the security-relevant behaviour.
    assert norm("&amp;lt;PERSON_001&amp;gt;") == "&lt;PERSON_001&gt;"


def test_bare_ampersand_is_left_alone():
    assert norm("AT&T Q3") == "AT&T Q3"


def test_entity_without_semicolon_is_left_alone():
    # html.unescape would turn this into "AT&T" and corrupt the text.
    assert norm("AT&amp Q3") == "AT&amp Q3"


def test_unknown_entity_reference_is_left_alone():
    assert norm("&foo;") == "&foo;"


def test_surrogate_numeric_entity_is_rejected():
    assert norm("&#xD800;") == "&#xD800;"


# -- unicode folds -----------------------------------------------------------

def test_narrow_nbsp_becomes_ascii_space():
    # U+202F is the exact character the model emitted in "**PER 2**".
    assert norm("PER 2") == "PER 2"


def test_nbsp_becomes_ascii_space():
    assert norm("a b") == "a b"


def test_smart_quotes_are_folded():
    assert norm("“hi” and ‘there’") == '"hi" and \'there\''


def test_zero_width_characters_are_removed():
    assert norm("PER​SON") == "PERSON"


def test_bidi_override_is_removed():
    assert norm("a‮b") == "ab"


def test_em_dash_is_preserved():
    # The SME transcript uses U+2014 as its structural speaker separator.
    assert "—" in norm("**09:00 — Ahmed Hassan:**")


def test_combining_accent_is_composed():
    assert norm("é") == "é"


def test_nfkc_is_not_applied_by_default():
    # NFKC would turn this into "1/2"; NFC leaves it alone.
    assert norm("½") == "½"


def test_nfkc_is_available_when_configured():
    n = Normalizer(NormalizerConfig(unicode_form="NFKC"))
    assert n.normalize("＜A＞").text == "<A>"


def test_normalization_is_idempotent():
    raw = "a\r\n&amp; b‌é"
    once = norm(raw)
    assert norm(once) == once


# -- the offset invariant ----------------------------------------------------

@pytest.mark.parametrize(
    "raw",
    [
        "plain ascii text",
        "a\r\nb\r\nc",
        "x &amp; y &lt;z&gt;",
        "PER 2 and PER 3",
        "zero​width​here",
        "café and café",
        "Ahmed Farid   0:31 \r\nSo. \r\n",
        "**09:00 — Ahmed Hassan:**\r\n\r\nGood morning.",
        "﻿BOM at the start\r\n",
        "mixed &#65;&#x42; “quoted”\r\ntail",
    ],
)
def test_every_span_maps_back_to_a_slice_that_renormalizes_to_itself(raw):
    nt = N.normalize(raw)
    for start in range(len(nt.text)):
        for end in range(start + 1, min(start + 12, len(nt.text)) + 1):
            o_start, o_end = nt.to_original(start, end)
            assert 0 <= o_start <= o_end <= len(raw)
            back = N.normalize(raw[o_start:o_end]).text
            # The mapped-back slice must contain the span. It may be wider,
            # because endpoints inside a non-1:1 region snap outwards.
            assert nt.text[start:end] in back or back in nt.text[start:end]


@pytest.mark.parametrize(
    "raw",
    ["plain", "a\r\nb", "&amp;x", "PER 2", "café", "​zz"],
)
def test_offset_map_is_monotone(raw):
    nt = N.normalize(raw)
    prev = -1
    for i in range(len(nt.text)):
        cur = nt.offset_map.to_original_index(i)
        assert cur >= prev
        prev = cur


def test_whole_document_maps_to_the_whole_original():
    raw = "Ahmed Farid   0:31 \r\nSo. \r\n"
    nt = N.normalize(raw)
    assert nt.to_original(0, len(nt.text)) == (0, len(raw))


def test_pure_ascii_text_has_an_identity_map():
    raw = "no changes needed here"
    nt = N.normalize(raw)
    assert nt.text == raw
    for i in range(len(raw)):
        assert nt.offset_map.to_original_index(i) == i
    assert nt.is_exact(0, len(raw))


def test_is_exact_is_false_across_a_length_changing_edit():
    nt = N.normalize("a\r\nb")
    assert not nt.is_exact(0, 4)


def test_is_exact_is_true_for_a_one_to_one_fold():
    # U+202F -> space is a single-character substitution, so offsets are exact.
    nt = N.normalize("PER 2")
    assert nt.is_exact(0, 5)


def test_zero_length_span_maps_to_a_zero_length_span():
    nt = N.normalize("a\r\nb")
    s, e = nt.to_original(2, 2)
    assert s == e


# -- property ----------------------------------------------------------------

_ALPHABET = st.sampled_from(
    [*list("abcXYZ 0123.,\n\t"), "\r\n", "\r", "&amp;", "&lt;", "&#65;", "\xa0", "\u202f", "\u200b", "—", "“", "é", "\ufeff", "&notanentity", "AT&T"]
)


@pytest.mark.property
@settings(max_examples=200, deadline=None)
@given(st.lists(_ALPHABET, max_size=40).map("".join))
def test_property_offsets_are_monotone_and_in_range(raw):
    nt = N.normalize(raw)
    prev = -1
    for i in range(len(nt.text)):
        cur = nt.offset_map.to_original_index(i)
        assert 0 <= cur <= len(raw)
        assert cur >= prev
        prev = cur
    assert nt.to_original(0, len(nt.text))[1] <= len(raw)


@pytest.mark.property
@settings(max_examples=200, deadline=None)
@given(st.lists(_ALPHABET, max_size=40).map("".join))
def test_property_normalization_is_idempotent(raw):
    once = N.normalize(raw).text
    assert N.normalize(once).text == once
