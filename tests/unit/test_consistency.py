"""The occurrence sweep: protecting every instance of an already-mapped value.

Detection is positional. A statistical detector may label a value once and
miss it two lines later; without this sweep the mapping would contain a value
while the document still showed it in plain text.
"""

from __future__ import annotations

import pytest

from privacy_gateway.entities.entity import DetectedEntity
from privacy_gateway.policy.actions import DEFAULT_RULES, Action
from privacy_gateway.policy.engine import PolicyDecision
from privacy_gateway.pseudonymization.consistency import expand_occurrences

PERSON = DEFAULT_RULES["PERSON"]
ORG = DEFAULT_RULES["ORGANIZATION"]


def ent(text, start, etype="PERSON", detector="ner", conf=0.9):
    return DetectedEntity(
        entity_type=etype, text=text, start=start, end=start + len(text),
        confidence=conf, detector=detector,
    )


def decide(entity, rule, action=Action.PSEUDONYMIZE):
    return PolicyDecision(entity, action, rule, "test")


def test_a_missed_occurrence_of_a_protected_name_is_recovered():
    text = "Ahmed Farid opened the call. Later, Ahmed Farid closed it."
    detected = ent("Ahmed Farid", 0)
    extra = expand_occurrences(text, [decide(detected, PERSON)])
    assert [(e.start, e.end) for e in extra] == [(36, 47)]


def test_an_already_covered_occurrence_is_not_duplicated():
    text = "Ahmed Farid opened the call."
    detected = ent("Ahmed Farid", 0)
    extra = expand_occurrences(text, [decide(detected, PERSON)])
    assert extra == ()


def test_only_transforming_decisions_are_swept():
    text = "Microsoft opened the call. Later, Microsoft closed it."
    detected = ent("Microsoft", 0, etype="ORGANIZATION")
    extra = expand_occurrences(text, [decide(detected, ORG, Action.ALLOW)])
    assert extra == ()


def test_a_short_case_insensitive_value_is_not_swept():
    # The floor that keeps an ordinary short word from matching everywhere.
    text = "the cat sat. a cat ran."
    detected = ent("cat", 4, etype="ORGANIZATION")
    extra = expand_occurrences(text, [decide(detected, ORG)])
    assert extra == ()


# -- the case-sensitive abbreviation floor -----------------------------------
#
# "SME"/"ESQ"/"CFE" recur throughout a formal transcript as titles and role
# acronyms. A detector missing the confidence bar on one occurrence (a
# plausible outcome for any single 3-letter token) used to leave that specific
# occurrence completely unswept, because the sweep's own length floor (4
# characters) rejected the value before it ever got a chance to search for it,
# regardless of the fact that abbreviation-shaped values are case-sensitive
# and therefore safe to sweep at any length.

def test_a_short_case_sensitive_abbreviation_is_swept():
    text = "Meeting Type: SME Consultation. The SME will attend."
    detected = ent("SME", 36, etype="ORGANIZATION", conf=0.99)
    extra = expand_occurrences(text, [decide(detected, ORG)])
    assert [(e.start, e.end) for e in extra] == [(14, 17)]


def test_the_sweep_never_matches_a_different_case_of_a_short_abbreviation():
    text = "SME Consultation involves an sme (lowercase, unrelated)."
    detected = ent("SME", 0, etype="ORGANIZATION", conf=0.99)
    extra = expand_occurrences(text, [decide(detected, ORG)])
    assert extra == ()  # only the identical-case "SME" would be swept, and it's covered


def test_a_case_insensitive_rule_type_still_uses_the_higher_floor_when_not_abbreviation_shaped():
    text = "the cat sat. a cat ran. a cat slept."
    detected = ent("cat", 4, etype="ORGANIZATION", conf=0.99)
    extra = expand_occurrences(text, [decide(detected, ORG)])
    assert extra == ()


@pytest.mark.parametrize("value", ["SME", "ESQ", "CFE", "EMA", "OR"])
def test_various_short_abbreviations_are_swept(value):
    text = f"first {value} then later {value} again."
    start = text.index(value)
    detected = ent(value, start, etype="ORGANIZATION", conf=0.99)
    extra = expand_occurrences(text, [decide(detected, ORG)])
    assert len(extra) == 1
