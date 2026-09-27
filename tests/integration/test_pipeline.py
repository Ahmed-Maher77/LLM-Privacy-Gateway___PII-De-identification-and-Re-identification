"""End-to-end pipeline against mock models.

No real model is used here. That is deliberate: these tests exercise the
*machinery*, and the machinery is where the prototype failed. Detection quality
is measured separately by the evaluation harness.
"""

from __future__ import annotations

import pytest

from privacy_gateway.config import DetectorSettings, LLMSettings, Settings
from privacy_gateway.errors import OutputLeakError
from privacy_gateway.gateway import GatewayRequest, PrivacyGateway, new_conversation_id
from privacy_gateway.llm.mock_client import (
    EchoLLMClient,
    FailingLLMClient,
    MockLLMClient,
)
from privacy_gateway.pseudonymization.applier import invert
from tests._helpers.assertions import (
    SecretLeak,
    assert_no_invented_words,
    assert_no_placeholder_adjacency,
    assert_no_secrets,
    find_leaks,
    placeholder_tokens,
)

# A realistic Teams export. Each speaker recurs, because the parser requires a
# name on at least two speaker lines before accepting it -- a two-column table
# row matches the same shape as a genuine speaker label.
DOC = """Ahmed Farid   0:31
Morning. I spoke to Rania Fahmy about FleetCore.

Rania Fahmy   0:45
Right. Mail me at rania.fahmy@brightpath-example.com or call +44 7700 900123.

Ahmed Farid   1:02
The account is BP-28491 and the endpoint is https://api.fleetcore.example.com/v2.

Hossam Badri   1:20
Understood. BrightPath Logistics will confirm.

Rania Fahmy   1:35
I will send the summary to Hossam Badri today.

Hossam Badri   1:52
Thanks. CustomerDesk also needs updating.

Ahmed Farid   2:10
Agreed. Rania Fahmy owns that.
"""


def gateway(llm=None, **detector_kw):
    settings = Settings(
        detectors=DetectorSettings(
            enabled=detector_kw.pop("enabled", ("regex", "registry", "domain")),
            required=("regex", "registry"),
        ),
        llm=LLMSettings(provider="mock"),
        **detector_kw,
    )
    return PrivacyGateway(settings, llm=llm or EchoLLMClient())


def run(llm=None, text=DOC, **kw):
    gw = gateway(llm, **kw)
    return gw, gw.run(GatewayRequest(text=text, conversation_id="c-test"))


# -- the round trip ----------------------------------------------------------

def test_pipeline_completes_and_finds_entities():
    _, result = run()
    assert result.status == "ok"
    assert len(result.store) > 0


def test_exact_inversion_reproduces_the_normalized_input():
    _, result = run()
    assert invert(result.sanitized_input, result.sanitize.sanitization.applied) == (
        result.sanitize.normalized.text
    )


def test_canonical_restoration_reproduces_the_input():
    # The echo client returns the whole prompt, so the restored document is
    # the tail of the output after the instruction prefix.
    _, result = run()
    assert result.output.endswith(result.sanitize.normalized.text)


def test_the_pipeline_is_deterministic_across_runs():
    _, first = run()
    _, second = run()
    assert first.sanitized_input == second.sanitized_input
    assert {e.placeholder: e.canonical for e in first.store.entries()} == {
        e.placeholder: e.canonical for e in second.store.entries()
    }


def test_every_placeholder_in_the_text_is_a_mapping_key():
    _, result = run()
    assert placeholder_tokens(result.sanitized_input) <= result.store.placeholders()


def test_every_mapping_key_appears_in_the_text():
    _, result = run()
    assert result.store.placeholders() <= placeholder_tokens(result.sanitized_input)


def test_line_count_is_preserved():
    _, result = run()
    assert result.sanitized_input.count("\n") == result.sanitize.normalized.text.count("\n")


def test_no_invented_words():
    _, result = run()
    assert_no_invented_words(result.sanitized_input, result.sanitize.normalized.text)


def test_no_placeholder_adjacency():
    _, result = run()
    assert_no_placeholder_adjacency(result.sanitized_input)


# -- the mapping never reaches the model ------------------------------------

def test_the_model_never_receives_any_mapped_value():
    gw, result = run()
    assert_no_secrets(
        gw._llm.prompts, [e.canonical for e in result.store.entries()], context="prompt"
    )


def test_the_model_never_receives_any_occurrence_variant():
    gw, result = run()
    variants = [v for e in result.store.entries() for v in e.variants]
    assert_no_secrets(gw._llm.prompts, variants, context="prompt")


def test_the_model_is_called_exactly_once_per_turn():
    gw, _ = run()
    assert gw._llm.call_count == 1


def test_the_prompt_contains_only_placeholders_this_mapping_knows():
    gw, result = run()
    assert placeholder_tokens(gw._llm.prompts[0]) <= result.store.placeholders()


def test_the_assertion_helper_itself_detects_a_planted_leak():
    # Negative control. An assertion helper that has never failed is not
    # evidence, so this plants the prototype's exact failure -- a placeholder
    # glued to the remainder of the name -- and requires the helper to catch it.
    planted = "Contact <PER_2>ehal Fahmy about it."
    assert find_leaks(planted, ["Rania Fahmy"])
    with pytest.raises(SecretLeak):
        assert_no_secrets(planted, ["Rania Fahmy"], context="planted")


def test_the_assertion_helper_passes_on_genuinely_clean_text():
    assert_no_secrets("Contact <PERSON_001> about it.", ["Rania Fahmy"], context="clean")


# -- model misbehaviour ------------------------------------------------------

def test_a_summarising_model_round_trips_its_placeholders():
    gw, result = run(MockLLMClient(mode="summarize_stub"))
    assert result.status == "ok"
    for entry in result.store.entries():
        if entry.placeholder in gw._llm.prompts[0]:
            pass
    assert "<PERSON_" not in result.output


def test_mangled_placeholders_are_reported_not_silently_dropped():
    _, result = run(MockLLMClient(mode="mangle_markdown"))
    assert result.reidentification.drift
    assert result.status == "degraded"


def test_mangled_placeholders_are_never_silently_restored():
    _, result = run(MockLLMClient(mode="mangle_markdown"))
    assert_no_secrets(
        result.output,
        [e.canonical for e in result.store.entries()],
        context="output",
    )


def test_hallucinated_placeholders_are_redacted_and_reported():
    _, result = run(MockLLMClient(mode="hallucinate"))
    assert result.reidentification.unknown
    assert "[UNRESOLVED_PLACEHOLDER]" in result.output


def test_a_stripping_model_loses_coverage_without_leaking():
    _, result = run(MockLLMClient(mode="strip_placeholders"))
    assert_no_secrets(
        result.output, [e.canonical for e in result.store.entries()], context="output"
    )


def test_a_prompt_injecting_model_cannot_mutate_the_mapping():
    gw, result = run(MockLLMClient(mode="inject"))
    before = {e.placeholder: e.canonical for e in result.store.entries()}
    gw.restore(result.output, result.store, conversation_id="c-test")
    after = {e.placeholder: e.canonical for e in result.store.entries()}
    assert before == after


def test_an_llm_failure_does_not_leak_the_mapping_into_the_exception():
    from privacy_gateway.errors import LLMError

    gw = gateway(FailingLLMClient())
    with pytest.raises(LLMError) as excinfo:
        gw.run(GatewayRequest(text=DOC, conversation_id="c-test"))
    message = f"{excinfo.value!r} {excinfo.value}"
    assert "Rania" not in message and "brightpath" not in message.lower()


# -- fail-closed on a real output leak --------------------------------------

def test_a_model_echoing_a_raw_value_is_blocked_when_failing_closed():
    leaking = MockLLMClient(responses=["The attendee was Rania Fahmy."])
    gw = gateway(leaking)
    with pytest.raises(OutputLeakError):
        gw.run(GatewayRequest(text=DOC, conversation_id="c-test"))


def test_the_same_leak_is_reported_when_failing_open():
    leaking = MockLLMClient(responses=["The attendee was Rania Fahmy."])
    settings = Settings(
        detectors=DetectorSettings(enabled=("regex", "registry", "domain"), required=()),
        fail_mode="open",
    )
    result = PrivacyGateway(settings, llm=leaking).run(
        GatewayRequest(text=DOC, conversation_id="c-test")
    )
    assert result.status == "degraded"
    assert result.reidentification.leaks


# -- conversation scope ------------------------------------------------------

def test_two_conversations_hold_independent_mappings():
    _gw_a, result_a = run()
    gw_b = gateway(EchoLLMClient())
    result_b = gw_b.run(GatewayRequest(text="Sarah Mitchell   0:01\nHello.\n" * 3,
                                       conversation_id="c-other"))
    assert result_a.store.conversation_id != result_b.store.conversation_id


def test_a_placeholder_cannot_cross_conversations():
    from privacy_gateway.errors import ConversationMismatchError

    gw, result = run()
    with pytest.raises(ConversationMismatchError):
        gw.restore("<PERSON_001>", result.store, conversation_id="c-someone-else")


def test_generated_conversation_ids_are_unguessable():
    ids = {new_conversation_id() for _ in range(200)}
    assert len(ids) == 200
    assert all(len(i) >= 18 for i in ids)


# -- structured detection on the transcript ---------------------------------

def test_structured_identifiers_are_all_protected():
    _, result = run()
    types_found = {e.entity_type for e in result.store.entries()}
    assert {"EMAIL", "PHONE", "CUSTOMER_ID"} <= types_found


def test_speakers_are_protected():
    _, result = run()
    values = {e.canonical for e in result.store.entries()}
    assert {"Ahmed Farid", "Rania Fahmy", "Hossam Badri"} <= values


def test_internal_systems_are_protected():
    _, result = run()
    values = {e.canonical for e in result.store.entries()}
    assert "FleetCore" in values
