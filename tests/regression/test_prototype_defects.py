"""Regression against the prototype's committed output.

Two halves.

The first half pins the *evidence*: the artifacts under fixtures/prototype_v0/
must continue to demonstrate the defects, otherwise the second half is
asserting against nothing. A regression suite whose fixture has quietly stopped
reproducing the bug is worse than no suite at all.

The second half runs the current pipeline over the same transcripts and asserts
the defects are gone. It needs no model: the deterministic, domain and registry
layers are enough to exercise every structural invariant, and detection quality
is measured separately by the evaluation harness.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from privacy_gateway.config import DetectorSettings, LLMSettings, Settings
from privacy_gateway.gateway import GatewayRequest, PrivacyGateway
from privacy_gateway.llm.mock_client import EchoLLMClient
from privacy_gateway.pseudonymization.applier import invert
from tests._helpers.assertions import (
    assert_no_invented_words,
    assert_no_placeholder_adjacency,
    placeholder_tokens,
    vocabulary,
)

NARROW_NBSP = " "

#: Placeholder-glued-to-remainder sites lifted verbatim from
#: fixtures/prototype_v0/pod_meeting.v0_output.txt.
PROTOTYPE_CORRUPTIONS = [
    "<PER_2>ehal",
    "<PER_13>rif",
    "<PER_23>y",
    "<PER_11>rtana",
    "<PER_11>ntent",
    "<PER_11>ntrol",
    "<LOC_1>honemi",
    "<PER_2>ice",
    "<PER_20>as",
    "<PER_21>ak",
]

#: Words that exist nowhere in the source transcript and were manufactured by
#: replacing a sub-word span.
PROTOTYPE_INVENTED_WORDS = [
    "ehal", "rif", "honemi", "rtana", "ntrol", "ntent",
    "nversation", "mposer", "ntract", "oaman", "abeeh", "oha",
]

#: Words the prototype destroyed that must survive intact.
MUST_SURVIVE = [
    "Nice", "Content", "Control", "Contract", "Conversation",
    "Cortana", "Noha", "Shalaby", "Halas", "Next",
]


def pipeline(text: str, conversation_id: str):
    """Deterministic layers only: no spaCy, no torch, no network."""
    settings = Settings(
        detectors=DetectorSettings(
            enabled=("regex", "registry", "domain"), required=("regex", "registry")
        )
    )
    gw = PrivacyGateway(settings, llm=EchoLLMClient())
    return gw, gw.run(GatewayRequest(text=text, conversation_id=conversation_id))


# ---------------------------------------------------------------------------
# 1. the evidence itself
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def v0_pod_output(prototype_fixtures_dir):
    return (prototype_fixtures_dir / "pod_meeting.v0_output.txt").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def v0_pod_run(prototype_fixtures_dir):
    return json.loads((prototype_fixtures_dir / "pod_meeting.v0_run.json").read_text("utf-8"))


@pytest.fixture(scope="module")
def v0_sme_run(prototype_fixtures_dir):
    return json.loads((prototype_fixtures_dir / "sme_meeting.v0_run.json").read_text("utf-8"))


@pytest.fixture(scope="module")
def v0_sme_output(prototype_fixtures_dir):
    return (prototype_fixtures_dir / "sme_meeting.v0_output.txt").read_text(encoding="utf-8")


@pytest.mark.parametrize("corruption", PROTOTYPE_CORRUPTIONS)
def test_the_fixture_still_demonstrates_the_corruption(v0_pod_output, corruption):
    assert corruption in v0_pod_output


def test_the_fixture_has_many_corrupted_sites(v0_pod_output):
    pattern = re.compile(r"<[A-Z]+_\d+>\w")
    assert len(pattern.findall(v0_pod_output)) > 100


def test_the_fixture_invented_words_absent_from_the_source(v0_pod_output, raw_transcript):
    masked = re.sub(r"<[A-Z]+_\d+>", " ", v0_pod_output)
    invented = vocabulary(masked) - vocabulary(raw_transcript("pod_meeting.txt"))
    assert len(invented) >= 20


def test_the_fixture_shows_the_narrow_nbsp_mangling(v0_pod_run):
    assert v0_pod_run["result"].count(NARROW_NBSP) > 50


def test_the_fixture_shows_restoration_was_a_total_no_op(v0_pod_run):
    # Not a partial failure: zero placeholders survived intact, so restore()
    # matched nothing at all.
    assert re.findall(r"<PER_\d+>", v0_pod_run["result"]) == []


def test_the_fixture_shows_a_placeholder_range_enumeration(v0_pod_run):
    assert re.search(r"PER[\s ]\d+[‑-]\d+", v0_pod_run["result"])


def test_the_fixture_shows_hallucinated_placeholders(v0_sme_run, v0_sme_output):
    in_output = set(re.findall(r"<(\w+_\d+)>", v0_sme_run["result"]))
    in_input = set(re.findall(r"<(\w+_\d+)>", v0_sme_output))
    assert {"PER_10", "PER_11", "PER_12"} <= (in_output - in_input)


def test_the_fixture_leaked_the_phone_and_account_id(v0_sme_output):
    assert "+44 7700 900123" in v0_sme_output
    assert "BP-28491" in v0_sme_output


# ---------------------------------------------------------------------------
# 2. the current pipeline on the same documents
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def pod(raw_transcript):
    return pipeline(raw_transcript("pod_meeting.txt"), "c-pod")


@pytest.fixture(scope="module")
def sme(raw_transcript):
    return pipeline(raw_transcript("sme_meeting_transcript.txt"), "c-sme")


@pytest.fixture(params=["pod", "sme"])
def both(request, pod, sme):
    return {"pod": pod, "sme": sme}[request.param]


# -- structural invariants ---------------------------------------------------

def test_pseudonymization_is_lossless(both):
    _, result = both
    assert invert(result.sanitized_input, result.sanitize.sanitization.applied) == (
        result.sanitize.normalized.text
    )


def test_no_invented_words(both):
    _, result = both
    assert_no_invented_words(result.sanitized_input, result.sanitize.normalized.text)


def test_no_placeholder_is_adjacent_to_a_word_character(both):
    _, result = both
    assert_no_placeholder_adjacency(result.sanitized_input)


def test_every_placeholder_in_the_text_is_a_mapping_key(both):
    _, result = both
    assert placeholder_tokens(result.sanitized_input) <= result.store.placeholders()


def test_every_mapping_key_appears_in_the_text(both):
    _, result = both
    assert result.store.placeholders() <= placeholder_tokens(result.sanitized_input)


def test_line_count_is_unchanged(both):
    _, result = both
    assert result.sanitized_input.count("\n") == result.sanitize.normalized.text.count("\n")


def test_the_run_is_reproducible(both):
    _, result = both
    settings = Settings(
        detectors=DetectorSettings(
            enabled=("regex", "registry", "domain"), required=("regex", "registry")
        )
    )
    again = PrivacyGateway(settings, llm=EchoLLMClient()).run(
        GatewayRequest(
            text=result.sanitize.normalized.original,
            conversation_id=result.store.conversation_id,
        )
    )
    assert again.sanitized_input == result.sanitized_input


# -- the specific defects ----------------------------------------------------

@pytest.mark.parametrize("corruption", PROTOTYPE_CORRUPTIONS)
def test_prototype_corruption_sites_are_absent(pod, corruption):
    _, result = pod
    assert corruption not in result.sanitized_input


@pytest.mark.parametrize("word", PROTOTYPE_INVENTED_WORDS)
def test_prototype_invented_words_are_absent(pod, word):
    # Compared as whole words: "ntrol" must not appear on its own, though
    # "control" legitimately contains those letters.
    _, result = pod
    masked = re.sub(r"<[A-Z][A-Z0-9]*_\d+>", " ", result.sanitized_input)
    assert word not in vocabulary(masked)


@pytest.mark.parametrize("word", MUST_SURVIVE)
def test_ordinary_words_survive(pod, word):
    _, result = pod
    assert word in vocabulary(result.sanitized_input)


def test_the_retired_placeholder_prefixes_are_gone(pod):
    # PER, LOC and MISC came from the NER model's raw label set. PERSON and
    # LOCATION replace the first two; MISC carries no privacy meaning and is
    # dropped entirely. ORG is deliberately NOT in this list -- it is still a
    # valid prefix, so the padding test below is what distinguishes the two
    # generations of placeholder.
    _, result = pod
    for prefix in ("<PER_", "<LOC_", "<MISC_"):
        assert prefix not in result.sanitized_input


def test_every_placeholder_uses_the_padded_grammar(both):
    # The prototype emitted <PER_1>; the current format is <PERSON_001>.
    # Padding is what makes a placeholder incapable of matching as a prefix of
    # a longer one.
    _, result = both
    loose = re.findall(r"<[A-Z][A-Z0-9]*_\d+>", result.sanitized_input)
    strict = re.findall(r"<[A-Z][A-Z0-9]*_\d{3,}>", result.sanitized_input)
    assert loose == strict
    assert strict


# -- participants ------------------------------------------------------------

POD_SPEAKERS = [
    "Ahmed Farid", "Ahmed Maher", "Ahmed Hamed",
    "Lamia Aly", "Rania Fahmy", "Hossam Badri",
]


@pytest.mark.parametrize("speaker", POD_SPEAKERS)
def test_every_pod_speaker_is_protected(pod, speaker):
    _, result = pod
    assert speaker in {e.canonical for e in result.store.entries()}


@pytest.mark.parametrize("speaker", POD_SPEAKERS)
def test_no_pod_speaker_survives_in_the_sanitized_text(pod, speaker):
    _, result = pod
    assert speaker not in result.sanitized_input


def test_every_speaker_header_line_is_fully_replaced(pod):
    _, result = pod
    header = re.compile(r"^\s*<PERSON_\d+>\s+\d+:\d{2}\s*$", re.MULTILINE)
    # pod_meeting.txt has 194 speaker lines.
    assert len(header.findall(result.sanitized_input)) >= 190


def test_the_ambiguous_bare_ahmed_is_protected_without_being_attributed(pod):
    # Three different Ahmeds speak, so a bare "Ahmed" cannot be resolved. It
    # gets its own placeholder and restores to exactly "Ahmed".
    _, result = pod
    ahmed = [e for e in result.store.entries() if e.canonical == "Ahmed"]
    assert len(ahmed) == 1
    assert len(ahmed[0].alias_candidates) == 3


# -- the SME false negatives -------------------------------------------------

SME_LEAKED_BY_PROTOTYPE = [
    "+44 7700 900123",
    "sarah.mitchell@brightpath-example.com",
    "michael.brown@brightpath-example.com",
    "omar.khaled@brightpath-example.com",
    "robert.taylor@example.org",
]


@pytest.mark.parametrize("value", SME_LEAKED_BY_PROTOTYPE)
def test_sme_values_the_prototype_leaked_are_now_protected(sme, value):
    _, result = sme
    assert value not in result.sanitized_input
    assert value in {e.canonical for e in result.store.entries()}


def test_excluded_identifiers_and_urls_pass_through_in_plain_text(sme):
    _, result = sme
    assert "BP-28491" in result.sanitized_input
    assert "https://api." in result.sanitized_input
    assert "brightpath-example.com/v2" in result.sanitized_input
    assert "<URL_" not in result.sanitized_input
    assert "<CUSTID_" not in result.sanitized_input
    assert "<ACCOUNT_" not in result.sanitized_input


@pytest.mark.parametrize(
    "system", ["FleetCore", "CustomerDesk", "BillingPro", "OpsHub"]
)
def test_internal_systems_are_protected(sme, system):
    _, result = sme
    assert system in {e.canonical for e in result.store.entries()}


@pytest.mark.parametrize("customer", ["BrightPath Logistics", "Green Valley Foods"])
def test_customers_are_protected(sme, customer):
    _, result = sme
    assert customer in {e.canonical for e in result.store.entries()}


# -- over-redaction guards ---------------------------------------------------

def test_vocabulary_retention_stays_high(both):
    # Over-redaction is the failure mode in the other direction: a summary in
    # which every noun is a placeholder is useless.
    _, result = both
    masked = re.sub(r"<[A-Z][A-Z0-9]*_\d+>", " ", result.sanitized_input)
    retained = len(vocabulary(masked)) / len(vocabulary(result.sanitize.normalized.text))
    assert retained >= 0.90


def test_public_product_names_are_not_protected(sme):
    _, result = sme
    values = {e.canonical for e in result.store.entries()}
    for public in ("Microsoft", "SharePoint", "Teams", "Azure"):
        assert public not in values


def test_dollar_amounts_are_preserved(sme):
    _, result = sme
    assert "$80,000" in result.sanitized_input
    assert "$180,000" in result.sanitized_input


def test_dates_are_detected_and_pseudonymized(sme):
    _, result = sme
    assert "September 22, 2026" not in result.sanitized_input
    assert "September 22, 2026" in {e.canonical for e in result.store.entries()}


# ---------------------------------------------------------------------------
# 3. what each configuration actually protects
# ---------------------------------------------------------------------------
#
# Found by running the real pipeline end to end: the deterministic-only
# configuration leaves two real names in the text it sends. Neither person
# speaks in the meeting (so the participant registry never sees them) and
# neither is in the domain lexicon, so only a model-backed layer can find them.
#
# This is not a defect -- it is the measured behaviour of a configuration that
# trades recall for a 120x speed-up, and config D in the evaluation sweep says
# the same thing (0.577 recall, leaking in 20 of 22 excerpts). It is pinned here
# because choosing the fast configuration for a document containing
# non-participant names is a privacy decision, and it should fail loudly if the
# trade-off ever changes silently.
#
# It also marks the boundary of the pre-send leak gate: the gate catches
# "detection succeeded but replacement failed". It cannot catch "detection never
# happened", because an undetected value is not in the mapping to be scanned for.

#: Mentioned in the SME transcript but never speaking, and absent from the
#: shipped domain lexicon.
NON_PARTICIPANT_NAMES = ["Robert Taylor", "James Anderson"]


@pytest.mark.parametrize("name", NON_PARTICIPANT_NAMES)
def test_deterministic_only_does_not_find_a_non_participant_name(sme, name):
    _, result = sme  # regex + registry + domain
    assert name not in {e.canonical for e in result.store.entries()}


@pytest.mark.parametrize("name", NON_PARTICIPANT_NAMES)
def test_deterministic_only_therefore_leaves_that_name_in_the_sanitized_text(sme, name):
    _, result = sme
    assert name in result.sanitized_input


@pytest.mark.requires_models
@pytest.mark.parametrize("name", NON_PARTICIPANT_NAMES)
def test_the_full_detector_set_does_find_it(raw_transcript, name):
    settings = Settings(
        detectors=DetectorSettings(
            enabled=("regex", "registry", "domain", "presidio", "ner"),
            required=("regex", "registry"),
        )
    )
    gateway = PrivacyGateway(settings, llm=EchoLLMClient())
    result = gateway.run(
        GatewayRequest(
            text=raw_transcript("sme_meeting_transcript.txt"), conversation_id="c-full"
        )
    )
    assert name not in result.sanitized_input
    assert name in {e.canonical for e in result.store.entries()}


# -- legal document captions & false-positive pre-send leak gate prevention --

def test_legal_hearing_caption_does_not_abort_pre_send_gate():
    """Pin fix for documented defect in LIMITATIONS.md: arbitration hearing caption block.

    Formerly caused false-positive pre-send gate abort (exit code 5) because
    caption field labels (e.g. 'Case No.', 'Job No.') were minted as PERSON entities
    with 2-character token 'No', causing un-swept prose occurrences to trigger leak alerts.
    """
    path = Path(__file__).resolve().parents[2] / "test_data" / "transcript_test_new_2.txt"
    if not path.exists():
        pytest.skip("transcript_test_new_2.txt fixture not found")
    text = path.read_text(encoding="utf-8")
    settings = Settings(
        detectors=DetectorSettings(
            enabled=("regex", "registry", "domain"),
            required=("regex", "registry"),
        ),
        llm=LLMSettings(provider="mock"),
    )
    gw = PrivacyGateway(settings, llm=EchoLLMClient())
    result = gw.run(GatewayRequest(text=text, conversation_id="c-legal-repro"))
    assert result.status == "ok"
    assert len(result.store) > 0

    # Ensure field labels were not registered as people
    names = {e.canonical.casefold() for e in result.store.entries()}
    assert "case no." not in names
    assert "job no." not in names
    assert "hearing date" not in names
    assert "hearing time" not in names
    assert "court reporter" not in names
    assert "counsel claimant" not in names
    assert "no" not in names

    # Ensure genuine dialogue phrases with "No" survive unmasked in the sanitized text
    assert "No further questions." in result.sanitized_input or "no further questions" in result.sanitized_input.casefold()


def test_similar_court_caption_formats_reject_labels():
    """Verify other legal/caption forms (Docket No., Claim No., File No., etc.) do not become participants."""
    caption_text = """=====================================================================
DEPOSITION TRANSCRIPT
=====================================================================
Docket No.:        CV-2025-00421
Claim No.:         CLM-88392-B
File No.:          FL-99120
Hearing Date:      April 14, 2025
Hearing Time:      09:00 AM – 12:00 PM
Court Reporter:    Alice Walker, CSR No. 11223
Job No.:           JOB-2025-412
=====================================================================

MS. LINDQVIST: Please state your name for the record.
THE WITNESS: My name is David Miller.
MS. LINDQVIST: Thank you. No further questions.
"""
    settings = Settings(
        detectors=DetectorSettings(
            enabled=("regex", "registry", "domain"),
            required=("regex", "registry"),
        ),
        llm=LLMSettings(provider="mock"),
    )
    gw = PrivacyGateway(settings, llm=EchoLLMClient())
    result = gw.run(GatewayRequest(text=caption_text, conversation_id="c-caption-test"))
    assert result.status == "ok"
    names = {e.canonical.casefold() for e in result.store.entries()}
    assert "docket no." not in names
    assert "claim no." not in names
    assert "file no." not in names
    assert "job no." not in names
    assert "no" not in names
    assert "No further questions." in result.sanitized_input

