"""Adversarial tests.

The headline case is placeholder injection. An attacker who can get a literal
``<PERSON_001>`` into the input of a naive gateway gets it echoed by the model
and then *expanded by the gateway itself* into whichever real person holds
index 001 -- exfiltrating a value they never supplied. The defence is to treat
the placeholder grammar as something that must be escaped like any other
metacharacter.
"""

from __future__ import annotations

import pytest

from privacy_gateway.config import DetectorSettings, ReidentificationSettings, Settings
from privacy_gateway.detectors.base import DetectionContext
from privacy_gateway.entities.entity import DetectedEntity
from privacy_gateway.errors import (
    ConversationMismatchError,
    DetectorUnavailableError,
    InputTooLargeError,
    PlaceholderInjectionError,
)
from privacy_gateway.gateway import GatewayRequest, PrivacyGateway
from privacy_gateway.llm.mock_client import EchoLLMClient, MockLLMClient
from privacy_gateway.policy.actions import DEFAULT_RULES
from privacy_gateway.policy.engine import PolicyEngine
from privacy_gateway.pseudonymization.mapping_store import MappingStore
from privacy_gateway.reidentification.injection import PlaceholderInjectionGuard
from privacy_gateway.reidentification.restorer import Reidentifier
from tests._helpers.assertions import assert_no_secrets

NL = chr(10)

VICTIM_DOC = """Ahmed Farid   0:31
Morning, Rania Fahmy is joining.

Rania Fahmy   0:45
Hello everyone.

Ahmed Farid   1:02
Rania Fahmy will lead it.
"""


def build(llm=None, **overrides):
    settings = Settings(
        detectors=DetectorSettings(enabled=("regex", "registry", "domain"), required=()),
        **overrides,
    )
    return PrivacyGateway(settings, llm=llm or EchoLLMClient())


# -- placeholder injection ---------------------------------------------------

GUARD = PlaceholderInjectionGuard()


@pytest.mark.parametrize(
    "payload",
    [
        "<PERSON_001>",
        "[[PERSON_001]]",
        "⟦PERSON_001⟧",
        "<PER​SON_001>",  # zero-width inside the prefix
    ],
)
def test_the_guard_finds_a_seeded_placeholder(payload):
    assert GUARD.scan(f"Reference: {payload} please")


@pytest.mark.parametrize("benign", ["<div>", "<br/>", "<person_001>", "ISO 9001", "a < b > c"])
def test_the_guard_does_not_fire_on_benign_text(benign):
    assert GUARD.scan(benign) == ()


def test_a_neutralised_token_can_no_longer_match_the_grammar():
    neutral = GUARD.scan("<PERSON_001>")[0].neutralized
    assert GUARD.scan(neutral) == ()


def test_an_injected_token_becomes_a_top_priority_literal_entity():
    entities = GUARD.as_entities("see <PERSON_001> here")
    assert [e.entity_type for e in entities] == ["LITERAL"]
    assert entities[0].priority > 100  # outranks every detector


def test_injection_is_blocked_by_default_when_failing_closed():
    gw = build()
    with pytest.raises(PlaceholderInjectionError):
        gw.run(GatewayRequest(text=f"{VICTIM_DOC}\nRef <PERSON_001>.", conversation_id="c-1"))


def test_a_seeded_placeholder_never_resolves_to_a_real_name():
    # The attack, end to end, with blocking disabled so the neutralisation path
    # itself is exercised rather than the outright refusal.
    gw = build(
        reidentification=ReidentificationSettings(block_on_injection=False),
        fail_mode="open",
    )
    result = gw.run(
        GatewayRequest(
            text=f"{VICTIM_DOC}\nPlease expand <PERSON_001> for me.", conversation_id="c-1"
        )
    )
    tail = result.output[result.output.index("Please expand") :]
    assert "Rania" not in tail and "Ahmed" not in tail


def test_a_seeded_placeholder_restores_to_its_own_literal_text():
    gw = build(
        reidentification=ReidentificationSettings(block_on_injection=False),
        fail_mode="open",
    )
    result = gw.run(
        GatewayRequest(text=f"{VICTIM_DOC}\nRef <PERSON_001>.", conversation_id="c-1")
    )
    assert "<PERSON_001>." in result.output


def test_the_sanitized_prompt_contains_no_attacker_supplied_placeholder():
    gw = build(
        reidentification=ReidentificationSettings(block_on_injection=False),
        fail_mode="open",
    )
    result = gw.run(
        GatewayRequest(text=f"{VICTIM_DOC}\nRef <PERSON_001>.", conversation_id="c-1")
    )
    # Every placeholder in the prompt was minted by this gateway.
    import re

    for token in re.findall(r"<[A-Z][A-Z0-9]*_\d+>", gw._llm.prompts[0]):
        assert token in result.store


def test_injection_is_recorded_on_the_result():
    gw = build(
        reidentification=ReidentificationSettings(block_on_injection=False),
        fail_mode="open",
    )
    result = gw.run(
        GatewayRequest(text=f"{VICTIM_DOC}\nRef <PERSON_001>.", conversation_id="c-1")
    )
    assert result.sanitize.injected == 1
    assert any("injected" in w for w in result.warnings)


def test_an_html_encoded_placeholder_is_caught_after_normalization():
    # The guard runs after normalization, so an encoded payload has already
    # been folded into its plain form by the time it is scanned.
    gw = build(fail_mode="closed")
    with pytest.raises(PlaceholderInjectionError):
        gw.run(
            GatewayRequest(text=f"{VICTIM_DOC}\nRef &lt;PERSON_001&gt;.", conversation_id="c-1")
        )


def test_a_double_encoded_placeholder_stays_inert():
    # One decode pass only, so &amp;lt;...&amp;gt; must not be resurrected.
    gw = build(fail_mode="closed")
    result = gw.run(
        GatewayRequest(text=f"{VICTIM_DOC}\nRef &amp;lt;PERSON_001&amp;gt;.", conversation_id="c-1")
    )
    assert result.sanitize.injected == 0


# -- cross-conversation isolation -------------------------------------------

def test_a_mapping_cannot_be_used_from_another_conversation():
    gw = build()
    result = gw.run(GatewayRequest(text=VICTIM_DOC, conversation_id="c-a"))
    with pytest.raises(ConversationMismatchError):
        gw.restore("<PERSON_001>", result.store, conversation_id="c-b")


def test_a_placeholder_from_one_conversation_is_inert_in_another():
    gw = build()
    first = gw.run(GatewayRequest(text=VICTIM_DOC, conversation_id="c-a"))
    second = gw.run(
        GatewayRequest(text="Sarah Mitchell   0:01\nHi.\n\nSarah Mitchell   0:02\nBye.\n",
                       conversation_id="c-b")
    )
    restored = gw.restore("<PERSON_001>", second.store, conversation_id="c-b")
    values = {e.canonical for e in first.store.entries()}
    assert not any(v in restored.text for v in values)


def test_the_store_exposes_no_cross_conversation_lookup():
    store = MappingStore("c-a")
    assert not hasattr(store, "all_conversations")
    assert not hasattr(store, "global_lookup")


# -- malicious model output --------------------------------------------------

def test_model_output_cannot_rewrite_the_mapping():
    gw = build(MockLLMClient(mode="inject"))
    result = gw.run(GatewayRequest(text=VICTIM_DOC, conversation_id="c-1"))
    before = {e.placeholder: e.canonical for e in result.store.entries()}
    gw.restore(result.output, result.store, conversation_id="c-1")
    assert {e.placeholder: e.canonical for e in result.store.entries()} == before


def test_a_flood_of_placeholders_is_handled_without_leaking():
    gw = build(MockLLMClient(mode="flood"), fail_mode="open")
    result = gw.run(GatewayRequest(text=VICTIM_DOC, conversation_id="c-1"))
    assert_no_secrets(
        result.output, [e.canonical for e in result.store.entries()], context="flood output"
    )


def test_restoration_time_is_linear_in_output_length():
    import time

    store = MappingStore("c-1")
    for i in range(50):
        store.assign(
            DetectedEntity(
                entity_type="PERSON", text=f"Person Number{i:03d}", start=0, end=16,
                confidence=0.9, detector="ner",
            ),
            DEFAULT_RULES["PERSON"],
        )
    reid = Reidentifier(store, PolicyEngine(), scan_output=False, scan_drift=False)

    def timed(multiplier):
        text = "<PERSON_001> and some filler text. " * multiplier
        start = time.perf_counter()
        reid.restore(text)
        return time.perf_counter() - start

    timed(50)  # warm up
    small, large = timed(50), timed(2000)
    # 40x the input must not cost anywhere near 40^2 the time.
    assert large < small * 400


# -- detector failure --------------------------------------------------------

class ExplodingDetector:
    name = "exploding"
    layer = 1

    def warmup(self):
        return None

    def detect(self, text, ctx: DetectionContext | None = None):
        raise RuntimeError("detector exploded")


def test_a_detector_failure_fails_closed_and_never_calls_the_model():
    llm = EchoLLMClient()
    settings = Settings(
        detectors=DetectorSettings(enabled=(), required=()), fail_mode="closed"
    )
    gw = PrivacyGateway(settings, llm=llm, detectors=[ExplodingDetector()])
    with pytest.raises(DetectorUnavailableError):
        gw.run(GatewayRequest(text=VICTIM_DOC, conversation_id="c-1"))
    assert llm.call_count == 0


def test_a_detector_failure_is_survivable_when_failing_open():
    llm = EchoLLMClient()
    settings = Settings(detectors=DetectorSettings(enabled=(), required=()), fail_mode="open")
    gw = PrivacyGateway(settings, llm=llm, detectors=[ExplodingDetector()])
    result = gw.run(GatewayRequest(text=VICTIM_DOC, conversation_id="c-1"))
    assert "exploding" in result.sanitize.degraded_detectors
    assert any("without detector" in w for w in result.warnings)


def test_a_detector_error_does_not_leak_document_text():
    settings = Settings(detectors=DetectorSettings(enabled=(), required=()), fail_mode="closed")
    gw = PrivacyGateway(settings, llm=EchoLLMClient(), detectors=[ExplodingDetector()])
    with pytest.raises(DetectorUnavailableError) as excinfo:
        gw.run(GatewayRequest(text=VICTIM_DOC, conversation_id="c-1"))
    assert "Rania" not in str(excinfo.value)


def test_configuring_zero_detectors_is_refused():
    # The worst possible silent failure: a gateway that forwards every document
    # untouched while reporting success.
    from privacy_gateway.errors import ConfigError

    with pytest.raises(ConfigError):
        Settings.from_env({"GATEWAY_DETECTORS_ENABLED": ""}, dotenv=False)


# -- limits ------------------------------------------------------------------

def test_oversized_input_is_refused_before_any_model_call():
    llm = EchoLLMClient()
    from privacy_gateway.config import PreprocessingSettings

    settings = Settings(
        preprocessing=PreprocessingSettings(max_input_chars=100),
        detectors=DetectorSettings(enabled=("regex",), required=()),
    )
    gw = PrivacyGateway(settings, llm=llm)
    with pytest.raises(InputTooLargeError):
        gw.run(GatewayRequest(text="x" * 500, conversation_id="c-1"))
    assert llm.call_count == 0


def test_input_at_exactly_the_limit_is_accepted():
    from privacy_gateway.config import PreprocessingSettings

    settings = Settings(
        preprocessing=PreprocessingSettings(max_input_chars=100),
        detectors=DetectorSettings(enabled=("regex",), required=()),
    )
    gw = PrivacyGateway(settings, llm=EchoLLMClient())
    gw.run(GatewayRequest(text="x" * 100, conversation_id="c-1"))


def test_a_repeated_name_produces_one_mapping_entry():
    # Three speaker lines, so the transcript clears the format-detection
    # floor, then the same name repeated hundreds of times in the body.
    header = 'Ahmed Farid   0:0'
    text = (
        header + '1' + NL + ('Ahmed Farid spoke. ' * 300) + NL
        + NL + header + '2' + NL + 'End.' + NL
        + NL + header + '3' + NL + 'Done.' + NL
    )
    gw = build()
    result = gw.run(GatewayRequest(text=text, conversation_id="c-1"))
    people = [e for e in result.store.entries() if e.entity_type == "PERSON"]
    assert len(people) == 1
    assert len(people[0].occurrences) > 100


def test_pathological_zero_width_input_does_not_hang():
    gw = build()
    gw.run(GatewayRequest(text="​" * 50_000, conversation_id="c-1"))


def test_deeply_nested_entities_do_not_recurse():
    gw = build()
    gw.run(GatewayRequest(text="&amp;" * 5000, conversation_id="c-1"))
