"""The policy engine.

Detection and protection are separate decisions. These tests pin that
separation: the same detected entity yields a different action depending on
configuration, the allowlist and the fail mode.
"""

from __future__ import annotations

import pytest

from privacy_gateway.entities.entity import DetectedEntity
from privacy_gateway.errors import ConfigError
from privacy_gateway.policy.actions import Action, EntityRule
from privacy_gateway.policy.allowlist import Allowlist
from privacy_gateway.policy.engine import PolicyConfig, PolicyEngine


def ent(text="Ahmed Farid", etype="PERSON", conf=0.95):
    return DetectedEntity(
        entity_type=etype, text=text, start=0, end=len(text),
        confidence=conf, detector="ner",
    )


# -- defaults ----------------------------------------------------------------

@pytest.mark.parametrize(
    "entity_type",
    ["PERSON", "EMAIL", "PHONE", "CUSTOMER_ID", "EMPLOYEE", "INTERNAL_SYSTEM", "INTERNAL_URL"],
)
def test_always_protected_types_are_pseudonymized(entity_type):
    engine = PolicyEngine()
    assert engine.decide(ent(etype=entity_type)).action is Action.PSEUDONYMIZE


def test_date_is_allowed_by_default():
    # Presidio's DATE_TIME fires on every Teams timestamp and markdown speaker
    # header; protecting them removes the transcript's structure.
    assert PolicyEngine().decide(ent("September 22, 2026", "DATE")).action is Action.ALLOW


def test_account_identifier_is_reversible_by_default():
    decision = PolicyEngine().decide(ent("GB29 NWBK 6016 1331 9268 19", "ACCOUNT_IDENTIFIER"))
    assert decision.action is Action.PSEUDONYMIZE
    assert decision.rule.restorable


def test_confidential_business_information_is_pseudonymized():
    decision = PolicyEngine().decide(
        ent("the pricing model", "CONFIDENTIAL_BUSINESS_INFORMATION", conf=0.9)
    )
    assert decision.action is Action.PSEUDONYMIZE


def test_person_like_types_share_the_person_counter_prefix():
    engine = PolicyEngine()
    prefixes = {
        engine.rule_for(t).placeholder_prefix for t in ("PERSON", "EMPLOYEE", "STAKEHOLDER")
    }
    assert prefixes == {"PERSON"}


def test_identifier_types_are_case_sensitive():
    engine = PolicyEngine()
    for t in ("EMAIL", "CUSTOMER_ID", "INTERNAL_URL", "CONTRACT", "ACCOUNT_IDENTIFIER"):
        assert engine.rule_for(t).case_sensitive


def test_name_types_are_not_case_sensitive():
    assert not PolicyEngine().rule_for("PERSON").case_sensitive


# -- precedence --------------------------------------------------------------

def test_allowlisted_value_is_allowed():
    engine = PolicyEngine(allowlist=Allowlist.parse(["ORGANIZATION\tMicrosoft"]))
    assert engine.decide(ent("Microsoft", "ORGANIZATION")).action is Action.ALLOW


def test_the_allowlist_is_type_scoped():
    engine = PolicyEngine(allowlist=Allowlist.parse(["ORGANIZATION\tMicrosoft"]))
    assert engine.decide(ent("Microsoft", "PERSON")).action is Action.PSEUDONYMIZE


def test_a_bare_allowlist_entry_applies_to_every_type():
    # "Cortana" is a product that generic NER labels as a person.
    engine = PolicyEngine(allowlist=Allowlist.parse(["Cortana"]))
    assert engine.decide(ent("Cortana", "PERSON")).action is Action.ALLOW
    assert engine.decide(ent("Cortana", "ORGANIZATION")).action is Action.ALLOW


def test_allowlist_matching_is_case_insensitive():
    engine = PolicyEngine(allowlist=Allowlist.parse(["ORGANIZATION\tMicrosoft"]))
    assert engine.decide(ent("microsoft", "ORGANIZATION")).action is Action.ALLOW


def test_the_denylist_overrides_the_allowlist():
    engine = PolicyEngine(
        allowlist=Allowlist.parse(["ORGANIZATION\tAcme"]),
        denylist=Allowlist.parse(["ORGANIZATION\tAcme"]),
    )
    decision = engine.decide(ent("Acme", "ORGANIZATION"))
    assert decision.action is Action.PSEUDONYMIZE
    assert decision.rule_id == "denylist"


def test_the_denylist_overrides_a_low_confidence_score():
    engine = PolicyEngine(denylist=Allowlist.parse(["ORGANIZATION\tAcme"]))
    assert engine.decide(ent("Acme", "ORGANIZATION", conf=0.01)).action is Action.PSEUDONYMIZE


# -- unknown types and thresholds -------------------------------------------

def test_an_unknown_type_is_protected_by_default():
    # A new detector emitting an unconfigured label must not silently leak.
    decision = PolicyEngine().decide(ent("something", "PASSPORT_NUMBER"))
    assert decision.action is Action.PSEUDONYMIZE
    assert decision.rule_id.startswith("unknown_type")


def test_below_threshold_is_allowed_when_failing_open():
    engine = PolicyEngine(fail_closed=False)
    assert engine.decide(ent(conf=0.10)).action is Action.ALLOW


def test_below_threshold_is_protected_when_failing_closed():
    # The asymmetry is the entire point of the fail mode.
    engine = PolicyEngine(fail_closed=True)
    decision = engine.decide(ent(conf=0.10))
    assert decision.action is Action.PSEUDONYMIZE
    assert decision.rule_id.startswith("threshold")


def test_the_decision_records_which_rule_fired():
    assert PolicyEngine().decide(ent()).rule_id == "type_default:PERSON"


def test_decide_all_preserves_order():
    engine = PolicyEngine()
    entities = [ent("Ahmed"), ent("a@b.com", "EMAIL")]
    assert [d.entity for d in engine.decide_all(entities)] == entities


def test_transformable_filters_out_allowed_entities():
    engine = PolicyEngine(allowlist=Allowlist.parse(["ORGANIZATION\tMicrosoft"]))
    decisions = engine.decide_all([ent("Microsoft", "ORGANIZATION"), ent("Ahmed Farid")])
    assert len(engine.transformable(decisions)) == 1


# -- configuration -----------------------------------------------------------

def test_policy_can_be_overridden_from_a_dict():
    config = PolicyConfig.from_dict({"entity": {"LOCATION": {"action": "allow"}}})
    assert PolicyEngine(config).decide(ent("Dubai", "LOCATION")).action is Action.ALLOW


def test_date_can_be_made_strict_by_configuration():
    config = PolicyConfig.from_dict({"entity": {"DATE": {"action": "pseudonymize"}}})
    assert PolicyEngine(config).decide(ent("2026-09-22", "DATE")).action is Action.PSEUDONYMIZE


def test_an_unknown_action_name_is_a_config_error():
    with pytest.raises(ConfigError):
        PolicyConfig.from_dict({"entity": {"PERSON": {"action": "obliterate"}}})


def test_a_threshold_outside_the_unit_interval_is_a_config_error():
    with pytest.raises(ConfigError):
        PolicyConfig.from_dict({"entity": {"PERSON": {"min_confidence": 2.0}}})


def test_a_missing_policy_file_falls_back_to_defaults(tmp_path):
    config = PolicyConfig.load(tmp_path / "absent.toml")
    assert config.rules["PERSON"].action is Action.PSEUDONYMIZE


def test_an_invalid_placeholder_prefix_is_rejected():
    with pytest.raises(ValueError):
        EntityRule(entity_type="PERSON", placeholder_prefix="person")


# -- actions -----------------------------------------------------------------

def test_redact_is_not_restorable():
    assert not EntityRule(entity_type="X", action=Action.REDACT).restorable


def test_pseudonymize_is_restorable():
    assert EntityRule(entity_type="X", action=Action.PSEUDONYMIZE).restorable


def test_decision_repr_does_not_contain_the_entity_text():
    assert "Ahmed" not in repr(PolicyEngine().decide(ent()))


# -- shipped configuration ---------------------------------------------------

def test_shipped_allowlist_exempts_public_products(repo_root):
    engine = PolicyEngine.from_paths(
        repo_root / "config" / "policy.toml",
        repo_root / "resources" / "public_entities.txt",
        repo_root / "resources" / "denylist.txt",
    )
    for name in ("Microsoft", "GitHub", "Teams", "Azure", "Cortana"):
        assert engine.decide(ent(name, "ORGANIZATION")).action is Action.ALLOW


def test_shipped_allowlist_still_protects_a_real_customer(repo_root):
    engine = PolicyEngine.from_paths(
        repo_root / "config" / "policy.toml",
        repo_root / "resources" / "public_entities.txt",
        repo_root / "resources" / "denylist.txt",
    )
    decision = engine.decide(ent("BrightPath Logistics", "CUSTOMER"))
    assert decision.action is Action.PSEUDONYMIZE


@pytest.mark.parametrize("assistant", ["Cortana", "Siri", "Alexa", "Copilot"])
def test_assistant_names_are_exempt_whatever_type_a_detector_assigns(repo_root, assistant):
    # Generic NER labels these as PEOPLE, not organisations. A type-scoped
    # entry would not match, and the product name would be pseudonymized --
    # which is how the prototype came to corrupt "Cortana" into <PER_11>rtana.
    engine = PolicyEngine.from_paths(
        repo_root / "config" / "policy.toml",
        repo_root / "resources" / "public_entities.txt",
        repo_root / "resources" / "denylist.txt",
    )
    for entity_type in ("PERSON", "ORGANIZATION", "LOCATION"):
        assert engine.decide(ent(assistant, entity_type)).action is Action.ALLOW


def test_a_type_scoped_entry_stays_scoped(repo_root):
    # Microsoft is allowlisted as an organisation only, so a PERSON called
    # Microsoft is still protected. Type-agnostic is opt-in, not the default.
    engine = PolicyEngine.from_paths(
        repo_root / "config" / "policy.toml",
        repo_root / "resources" / "public_entities.txt",
        repo_root / "resources" / "denylist.txt",
    )
    assert engine.decide(ent("Microsoft", "ORGANIZATION")).action is Action.ALLOW
    assert engine.decide(ent("Microsoft", "PERSON")).action is Action.PSEUDONYMIZE
