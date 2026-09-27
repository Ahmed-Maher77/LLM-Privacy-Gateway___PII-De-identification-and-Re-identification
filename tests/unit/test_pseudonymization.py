"""Placeholders, the mapping store and offset-based replacement.

The two tests that matter most are
``test_replacement_is_by_offset_not_by_string_replace`` and
``test_a_single_character_entity_cannot_corrupt_other_words``: together they
pin the exact defect that produced ``<PER_2>ehal Fahmy`` and ``<PER_2>ice.``
in the prototype's committed output.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from privacy_gateway.entities.entity import DetectedEntity
from privacy_gateway.errors import AggregationInvariantError, ConversationMismatchError
from privacy_gateway.policy.actions import DEFAULT_RULES, Action, EntityRule
from privacy_gateway.policy.engine import PolicyDecision, PolicyEngine
from privacy_gateway.pseudonymization.applier import Pseudonymizer, invert
from privacy_gateway.pseudonymization.mapping_store import MappingStore, identity_key
from privacy_gateway.pseudonymization.placeholders import (
    PlaceholderFormat,
    find_placeholders,
    format_placeholder,
    parse_placeholder,
)

PERSON = DEFAULT_RULES["PERSON"]
EMAIL = DEFAULT_RULES["EMAIL"]


def ent(text, start, etype="PERSON", detector="ner", conf=0.9):
    return DetectedEntity(
        entity_type=etype, text=text, start=start, end=start + len(text),
        confidence=conf, detector=detector,
    )


def decide(entity, rule=PERSON, action=Action.PSEUDONYMIZE):
    return PolicyDecision(entity, action, rule, "test")


def sanitize(text, entities, rules=None):
    store = MappingStore("c-test")
    rules = rules or {}
    decisions = [decide(e, rules.get(e.entity_type, PERSON)) for e in entities]
    return Pseudonymizer(store).apply(text, decisions), store


# -- placeholder format ------------------------------------------------------

def test_placeholder_format_is_zero_padded():
    assert format_placeholder("PERSON", 1) == "<PERSON_001>"


def test_index_grows_beyond_the_padding():
    assert format_placeholder("PERSON", 1000) == "<PERSON_1000>"


def test_a_placeholder_round_trips_through_the_parser():
    assert parse_placeholder("<PERSON_001>") == ("PERSON", 1)


@pytest.mark.parametrize(
    "token", ["<div>", "<br/>", "<PERSON>", "<person_001>", "<PERSON_>", "PERSON_001", "<_001>"]
)
def test_non_placeholders_do_not_parse(token):
    assert parse_placeholder(token) is None


def test_a_placeholder_is_not_a_prefix_of_a_longer_one():
    # This is what made the prototype sort its mapping by length: a sequential
    # str.replace of <PER_1> before <PER_11> corrupts the latter. Anchoring on
    # the closing delimiter makes the problem impossible.
    text = "<PERSON_001> and <PERSON_0011>"
    assert [m.group() for m in find_placeholders(text)] == ["<PERSON_001>", "<PERSON_0011>"]


def test_iso_standards_and_model_names_are_not_placeholders():
    assert [m.group() for m in find_placeholders("ISO 9001 and GPT 4 and PER 2")] == []


def test_the_guillemet_style_is_available():
    fmt = PlaceholderFormat(style="guillemet")
    rendered = fmt.render("PERSON", 1)
    assert fmt.parse(rendered) == ("PERSON", 1)
    assert "<" not in rendered  # markdown- and HTML-inert


@pytest.mark.property
@settings(max_examples=200, deadline=None)
@given(st.integers(min_value=1, max_value=999_999))
def test_property_every_rendered_placeholder_parses(index):
    assert parse_placeholder(format_placeholder("PERSON", index)) == ("PERSON", index)


# -- identity ----------------------------------------------------------------

def test_the_same_surface_form_reuses_one_placeholder():
    store = MappingStore("c-1")
    a = store.assign(ent("Ahmed Farid", 0), PERSON)
    b = store.assign(ent("Ahmed Farid", 50), PERSON)
    assert a == b == "<PERSON_001>"
    assert len(store) == 1


def test_different_values_get_different_placeholders():
    store = MappingStore("c-1")
    assert store.assign(ent("Ahmed Farid", 0), PERSON) != store.assign(
        ent("Rania Fahmy", 20), PERSON
    )


def test_counters_are_independent_per_prefix():
    store = MappingStore("c-1")
    assert store.assign(ent("Ahmed", 0), PERSON) == "<PERSON_001>"
    assert store.assign(ent("a@b.com", 10, "EMAIL"), EMAIL) == "<EMAIL_001>"


def test_case_variants_share_a_placeholder_for_case_insensitive_types():
    store = MappingStore("c-1")
    a = store.assign(ent("Ahmed Farid", 0), PERSON)
    b = store.assign(ent("ahmed farid", 50), PERSON)
    assert a == b


def test_case_variants_are_recorded_for_reporting():
    store = MappingStore("c-1")
    store.assign(ent("Ahmed Farid", 0), PERSON)
    store.assign(ent("ahmed farid", 50), PERSON)
    assert store.get("<PERSON_001>").variants == {"Ahmed Farid", "ahmed farid"}


def test_case_variants_do_not_share_for_case_sensitive_types():
    store = MappingStore("c-1")
    a = store.assign(ent("A@B.com", 0, "EMAIL"), EMAIL)
    b = store.assign(ent("a@b.com", 20, "EMAIL"), EMAIL)
    assert a != b


def test_whitespace_is_collapsed_for_identity():
    assert identity_key("PERSON", "Ahmed  Farid", case_sensitive=False) == identity_key(
        "PERSON", "Ahmed Farid", case_sensitive=False
    )


def test_a_possessive_does_not_create_a_second_entity():
    assert identity_key("PERSON", "Sarah's", case_sensitive=False) == identity_key(
        "PERSON", "Sarah", case_sensitive=False
    )


def test_identity_never_collapses_across_types():
    store = MappingStore("c-1")
    a = store.assign(ent("Dubai", 0, "LOCATION"), DEFAULT_RULES["LOCATION"])
    b = store.assign(ent("Dubai", 40, "ORGANIZATION"), DEFAULT_RULES["ORGANIZATION"])
    assert a != b


def test_occurrences_accumulate():
    store = MappingStore("c-1")
    store.assign(ent("Ahmed Farid", 0), PERSON)
    store.assign(ent("Ahmed Farid", 50), PERSON)
    assert len(store.get("<PERSON_001>").occurrences) == 2


# -- replacement -------------------------------------------------------------

def test_replacement_is_by_offset_not_by_string_replace():
    # "N" appears all over this sentence; only the named span may change.
    text = "Nice. Rania Fahmy is here. No news."
    result, _ = sanitize(text, [ent("Rania Fahmy", 6)])
    assert result.text == "Nice. <PERSON_001> is here. No news."


def test_a_single_character_entity_cannot_corrupt_other_words():
    # The literal <PER_2>ice. defect, reproduced at unit scale.
    text = "Nice. Rania is here."
    result, _ = sanitize(text, [ent("N", 0)])
    assert result.text == "<PERSON_001>ice. Rania is here."
    assert result.text.count("<PERSON_001>") == 1


def test_replacement_applies_right_to_left_so_later_offsets_stay_valid():
    text = "Ahmed met Rania and Hossam."
    entities = [ent("Ahmed", 0), ent("Rania", 10), ent("Hossam", 20)]
    result, _ = sanitize(text, entities)
    assert result.text == "<PERSON_001> met <PERSON_002> and <PERSON_003>."


def test_repeated_entities_reuse_their_placeholder_in_the_text():
    text = "Ahmed called. Ahmed left."
    result, store = sanitize(text, [ent("Ahmed", 0), ent("Ahmed", 14)])
    assert result.text == "<PERSON_001> called. <PERSON_001> left."
    assert len(store) == 1


def test_placeholder_numbering_follows_document_order():
    text = "Zoe met Adam."
    result, _ = sanitize(text, [ent("Adam", 8), ent("Zoe", 0)])
    assert result.text == "<PERSON_001> met <PERSON_002>."


def test_no_original_value_survives_in_the_output():
    text = "Ahmed Farid and Rania Fahmy."
    result, store = sanitize(text, [ent("Ahmed Farid", 0), ent("Rania Fahmy", 16)])
    for entry in store.entries():
        assert entry.canonical not in result.text


def test_an_empty_decision_list_leaves_the_text_untouched():
    result, store = sanitize("nothing here", [])
    assert result.text == "nothing here"
    assert len(store) == 0


def test_an_allowed_entity_is_not_replaced():
    text = "Microsoft and Ahmed."
    store = MappingStore("c-1")
    decisions = [
        decide(ent("Microsoft", 0, "ORGANIZATION"), DEFAULT_RULES["ORGANIZATION"], Action.ALLOW),
        decide(ent("Ahmed", 14)),
    ]
    result = Pseudonymizer(store).apply(text, decisions)
    assert result.text == "Microsoft and <PERSON_001>."


def test_redaction_produces_an_irreversible_marker():
    text = "card 4539578763621486 here"
    store = MappingStore("c-1")
    decisions = [
        decide(
            ent("4539578763621486", 5, "CREDIT_CARD"),
            EntityRule(entity_type="CREDIT_CARD", action=Action.REDACT, placeholder_prefix="CARD"),
            Action.REDACT,
        )
    ]
    result = Pseudonymizer(store).apply(text, decisions)
    assert result.text == "card [REDACTED:CREDIT_CARD] here"
    assert len(store) == 0


def test_overlapping_decisions_are_refused():
    text = "Rania Fahmy is here."
    store = MappingStore("c-1")
    decisions = [decide(ent("Rania Fahmy", 0)), decide(ent("Fahmy", 6))]
    with pytest.raises(AggregationInvariantError):
        Pseudonymizer(store).apply(text, decisions)


def test_a_span_disagreeing_with_the_text_is_refused():
    store = MappingStore("c-1")
    bad = DetectedEntity(
        entity_type="PERSON", text="Ahmed", start=0, end=5, confidence=0.9, detector="qwen"
    )
    with pytest.raises(AggregationInvariantError):
        Pseudonymizer(store).apply("Rania Fahmy is here.", [decide(bad)])


# -- exact inversion ---------------------------------------------------------

def test_inversion_reproduces_the_input_exactly():
    text = "Ahmed met Rania and ahmed again."
    result, _ = sanitize(text, [ent("Ahmed", 0), ent("Rania", 10), ent("ahmed", 20)])
    assert invert(result.text, result.applied) == text


@pytest.mark.property
@settings(max_examples=150, deadline=None)
@given(
    st.lists(
        st.sampled_from(["Ahmed", "Rania", "Hossam", "the", "met", ".", " ", "\n", "a@b.com"]),
        min_size=1,
        max_size=30,
    )
)
def test_property_inversion_is_always_exact(tokens):
    text = "".join(tokens)
    names = ["Ahmed", "Rania", "Hossam"]
    entities, taken = [], []
    for name in names:
        start = 0
        while (idx := text.find(name, start)) != -1:
            if not any(s < idx + len(name) and idx < e for s, e in taken):
                entities.append(ent(name, idx))
                taken.append((idx, idx + len(name)))
            start = idx + len(name)
    entities.sort(key=lambda e: e.start)
    result, _ = sanitize(text, entities)
    assert invert(result.text, result.applied) == text


# -- conversation scope ------------------------------------------------------

def test_two_conversations_have_independent_counters():
    a, b = MappingStore("c-a"), MappingStore("c-b")
    assert a.assign(ent("Ahmed", 0), PERSON) == b.assign(ent("Rania", 0), PERSON)


def test_a_mismatched_conversation_id_is_refused():
    store = MappingStore("c-a")
    with pytest.raises(ConversationMismatchError):
        store.require_conversation("c-b")


def test_a_conversation_id_is_required():
    with pytest.raises(ValueError):
        MappingStore("")


# -- serialisation and safety ------------------------------------------------

def test_a_redacted_serialisation_contains_no_values():
    store = MappingStore("c-1")
    store.assign(ent("Ahmed Farid", 0), PERSON)
    assert "Ahmed" not in repr(store.to_dict(include_values=False))


def test_a_redacted_serialisation_cannot_be_rebuilt_into_a_mapping():
    store = MappingStore("c-1")
    store.assign(ent("Ahmed Farid", 0), PERSON)
    with pytest.raises(ValueError):
        MappingStore.from_dict(store.to_dict(include_values=False))


def test_a_full_serialisation_round_trips():
    store = MappingStore("c-1")
    store.assign(ent("Ahmed Farid", 0), PERSON)
    rebuilt = MappingStore.from_dict(store.to_dict(include_values=True))
    assert rebuilt.get("<PERSON_001>").canonical == "Ahmed Farid"


def test_the_safe_summary_contains_no_values():
    store = MappingStore("c-1")
    store.assign(ent("Ahmed Farid", 0), PERSON)
    assert "Ahmed" not in repr(store.to_safe_summary())


def test_store_repr_contains_no_values():
    store = MappingStore("c-1")
    store.assign(ent("Ahmed Farid", 0), PERSON)
    assert "Ahmed" not in repr(store)


def test_mapping_entry_repr_contains_no_values():
    store = MappingStore("c-1")
    store.assign(ent("Ahmed Farid", 0), PERSON)
    assert "Ahmed" not in repr(store.get("<PERSON_001>"))


def test_ambiguous_candidates_are_carried_into_the_mapping():
    store = MappingStore("c-1")
    entity = ent("Ahmed", 0).with_metadata(candidates=("Ahmed Farid", "Ahmed Hamed"))
    store.assign(entity, PERSON)
    assert store.get("<PERSON_001>").alias_candidates == ("Ahmed Farid", "Ahmed Hamed")


def test_policy_engine_and_store_agree_on_prefixes():
    engine = PolicyEngine()
    store = MappingStore("c-1")
    placeholder = store.assign(ent("Ahmed", 0), engine.rule_for("PERSON"))
    assert placeholder.startswith("<PERSON_")


# -- abbreviation-shaped values are case-sensitive regardless of type -------
#
# "OR" (Oregon's postal abbreviation) detected as LOCATION at NER confidence
# 1.00 -- a confidence gate cannot filter that out, the model is genuinely
# (over)confident -- then case-insensitive identity merged it with every
# ordinary lowercase "or" elsewhere in the document, and each one was reported
# as a leak of the mapped value.

def test_an_abbreviation_shaped_value_does_not_merge_with_an_ordinary_word():
    from privacy_gateway.pseudonymization.mapping_store import is_abbreviation_shaped

    store = MappingStore("c-1")
    a = store.assign(ent("OR", 0, "LOCATION"), DEFAULT_RULES["LOCATION"])
    b = store.assign(ent("or", 20, "LOCATION"), DEFAULT_RULES["LOCATION"])
    assert a != b
    assert is_abbreviation_shaped("OR")
    assert not is_abbreviation_shaped("or")  # lowercase: ordinary word, not an abbreviation


def test_an_abbreviation_shaped_value_still_merges_with_itself():
    store = MappingStore("c-1")
    a = store.assign(ent("NYC", 0, "LOCATION"), DEFAULT_RULES["LOCATION"])
    b = store.assign(ent("NYC", 30, "LOCATION"), DEFAULT_RULES["LOCATION"])
    assert a == b


@pytest.mark.parametrize(
    "value,expected",
    [
        ("OR", True), ("NYC", True), ("U.S.", True), ("or", False),
        ("Ahmed", False), ("BrightPath", False), ("A", False), ("ABCDEFG", False),
    ],
)
def test_is_abbreviation_shaped(value, expected):
    from privacy_gateway.pseudonymization.mapping_store import is_abbreviation_shaped

    assert is_abbreviation_shaped(value) is expected
