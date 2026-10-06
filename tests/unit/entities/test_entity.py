"""The entity model's own invariants."""

from __future__ import annotations

import pytest

from privacy_gateway.entities.entity import DetectedEntity, make_entity

TEXT = "Rania Fahmy said hi to Hossam Badri."


def _entity(**kw):
    defaults = dict(
        entity_type="PERSON", text="Rania Fahmy", start=0, end=11,
        confidence=0.9, detector="test",
    )
    return DetectedEntity(**{**defaults, **kw})


def test_entity_is_frozen():
    e = _entity()
    with pytest.raises(AttributeError):
        e.start = 5


def test_entity_is_hashable():
    assert len({_entity(), _entity()}) == 1


def test_metadata_is_not_mutable_through_the_entity():
    e = _entity(metadata={"a": 1})
    with pytest.raises(TypeError):
        e.metadata["b"] = 2


def test_negative_start_rejected():
    with pytest.raises(ValueError):
        _entity(start=-1, end=3, text="abc")


def test_end_not_greater_than_start_rejected():
    with pytest.raises(ValueError):
        _entity(start=5, end=5, text="")


def test_span_length_must_match_text_length():
    # The invariant that would have caught the prototype's word/offset mismatch.
    with pytest.raises(ValueError):
        _entity(start=0, end=5, text="Rania Fahmy")


def test_confidence_outside_unit_interval_rejected():
    with pytest.raises(ValueError):
        _entity(confidence=1.5)


def test_lowercase_entity_type_rejected():
    with pytest.raises(ValueError):
        _entity(entity_type="person")


def test_length_property_equals_end_minus_start():
    assert _entity().length == 11


def test_shifted_moves_both_offsets_and_keeps_text():
    e = _entity().shifted(100)
    assert (e.start, e.end, e.text) == (100, 111, "Rania Fahmy")


# -- the repr guarantee ------------------------------------------------------

def test_repr_never_contains_the_matched_text():
    e = _entity()
    assert "Rania" not in repr(e)
    assert "Fahmy" not in repr(e)


def test_str_never_contains_the_matched_text():
    assert "Rania" not in str(_entity())


def test_fstring_interpolation_is_safe():
    # This is the realistic leak vector: logger.debug(f"resolved {entity}").
    e = _entity()
    assert "Rania" not in f"resolved {e}"


def test_repr_of_a_list_of_entities_is_safe():
    assert "Rania" not in repr([_entity()])


def test_fingerprint_is_stable_for_equal_values():
    assert _entity().fingerprint() == _entity().fingerprint()


def test_fingerprint_differs_for_different_text():
    assert _entity().fingerprint() != _entity(text="Hossam Badri", start=23, end=35).fingerprint()


# -- make_entity: text is re-read, never trusted -----------------------------

def test_make_entity_reads_text_from_source():
    e = make_entity(
        text_source=TEXT, start=0, end=11, entity_type="PERSON",
        confidence=0.9, detector="ner",
    )
    assert e.text == "Rania Fahmy"


def test_make_entity_ignores_a_wrong_reported_text():
    # Hugging Face reports word="N" for a sub-word fragment; we must not use it.
    e = make_entity(
        text_source=TEXT, start=0, end=11, entity_type="PERSON",
        confidence=0.9, detector="ner", reported_text="N",
    )
    assert e.text == "Rania Fahmy"
    assert e.metadata["reported_text_mismatch"] is True


def test_make_entity_does_not_flag_a_matching_reported_text():
    e = make_entity(
        text_source=TEXT, start=0, end=11, entity_type="PERSON",
        confidence=0.9, detector="ner", reported_text="Rania Fahmy",
    )
    assert "reported_text_mismatch" not in e.metadata


def test_make_entity_rejects_a_span_past_the_end_of_the_source():
    with pytest.raises(ValueError):
        make_entity(
            text_source=TEXT, start=0, end=len(TEXT) + 10, entity_type="PERSON",
            confidence=0.9, detector="qwen",
        )
