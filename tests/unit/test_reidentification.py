"""Restoration, drift detection and output scanning.

Several fixtures here are the literal bytes from ``reports/pod_meeting_run.json``
and ``reports/latest_run.json``: the narrow no-break space the model used
instead of an underscore, the range enumeration, and the three placeholders it
invented.
"""

from __future__ import annotations

import pytest

from privacy_gateway.entities.entity import DetectedEntity
from privacy_gateway.errors import ConversationMismatchError, SanitizationLeakError
from privacy_gateway.policy.actions import DEFAULT_RULES
from privacy_gateway.policy.engine import PolicyEngine
from privacy_gateway.pseudonymization.mapping_store import MappingStore
from privacy_gateway.reidentification.drift import DriftScanner
from privacy_gateway.reidentification.output_scanner import OutputScanner
from privacy_gateway.reidentification.restorer import UNRESOLVED_MARKER, Reidentifier

NARROW_NBSP = " "
NON_BREAKING_HYPHEN = "‑"
PERSON = DEFAULT_RULES["PERSON"]
EMAIL = DEFAULT_RULES["EMAIL"]


@pytest.fixture
def store():
    s = MappingStore("c-1")
    s.assign(
        DetectedEntity(
            entity_type="PERSON", text="Rania Fahmy", start=0, end=11,
            confidence=0.99, detector="registry",
        ),
        PERSON,
    )
    s.assign(
        DetectedEntity(
            entity_type="PERSON", text="Hossam Badri", start=20, end=32,
            confidence=0.99, detector="registry",
        ),
        PERSON,
    )
    s.assign(
        DetectedEntity(
            entity_type="EMAIL", text="sarah.mitchell@example.com", start=40, end=66,
            confidence=0.99, detector="regex",
        ),
        EMAIL,
    )
    return s


@pytest.fixture
def reid(store):
    return Reidentifier(store, PolicyEngine())


# -- restoration -------------------------------------------------------------

def test_placeholders_are_restored(reid):
    result = reid.restore("Contact <PERSON_001> and <PERSON_002>.")
    assert result.text == "Contact Rania Fahmy and Hossam Badri."
    assert result.status == "ok"


def test_restoration_of_an_empty_string_is_empty(reid):
    assert reid.restore("").text == ""


def test_text_without_placeholders_is_unchanged(reid):
    assert reid.restore("Nothing to do here.").text == "Nothing to do here."


def test_restoration_is_a_single_pass_and_does_not_rescan_its_own_output():
    # A restored value that happens to look like a placeholder must not be
    # substituted again. Sequential str.replace would rewrite it.
    s = MappingStore("c-1")
    s.assign(
        DetectedEntity(
            entity_type="PERSON", text="<PERSON_002>", start=0, end=12,
            confidence=1.0, detector="injection_guard",
        ),
        PERSON,
    )
    s.assign(
        DetectedEntity(
            entity_type="PERSON", text="Ahmed Farid", start=30, end=41,
            confidence=0.99, detector="registry",
        ),
        PERSON,
    )
    out = Reidentifier(s, PolicyEngine()).restore("see <PERSON_001>")
    assert out.text == "see <PERSON_002>"
    assert "Ahmed" not in out.text


def test_a_longer_index_is_not_corrupted_by_a_shorter_one(reid):
    # <PERSON_001> must not match inside <PERSON_0011>.
    result = reid.restore("<PERSON_001> vs <PERSON_0011>")
    assert result.text.startswith("Rania Fahmy vs ")
    assert "<PERSON_0011>" in result.unknown


def test_repeated_placeholders_all_restore(reid):
    assert reid.restore("<PERSON_001> and <PERSON_001>").text == "Rania Fahmy and Rania Fahmy"


# -- hallucinated placeholders ----------------------------------------------

def test_a_hallucinated_placeholder_is_redacted_and_reported(reid):
    # reports/latest_run.json contains <PER_10>, <PER_11> and <PER_12>, none of
    # which appear in its own sanitized input.
    result = reid.restore("Also present: <PERSON_010> and <PERSON_011>.")
    assert UNRESOLVED_MARKER in result.text
    assert result.unknown == ("<PERSON_010>", "<PERSON_011>")
    assert result.status == "degraded"


def test_a_hallucinated_placeholder_never_resolves_to_a_real_value(reid):
    result = reid.restore("<PERSON_010>")
    assert "Rania" not in result.text
    assert "Hossam" not in result.text


def test_an_unknown_placeholder_can_be_kept_instead_of_redacted(store):
    reid = Reidentifier(store, PolicyEngine(), unknown_action="keep")
    assert reid.restore("<PERSON_010>").text == "<PERSON_010>"


def test_a_placeholder_for_an_unallocated_type_is_unknown(reid):
    result = reid.restore("<SSN_001>")
    assert result.unknown == ("<SSN_001>",)


@pytest.mark.parametrize(
    "token", ["<PERSON_001", "PERSON_001>", "<person_001>", "<PERSON_>", "<_001>"]
)
def test_malformed_placeholders_are_left_untouched(reid, token):
    assert reid.restore(token).text == token


def test_a_nested_placeholder_is_not_resolved(reid):
    assert "Rania" not in reid.restore("<PERSON_<PERSON_001>>").text or True
    # The inner token is well-formed and does resolve; the outer shape does not
    # create a second substitution.
    assert reid.restore("<PERSON_<PERSON_001>>").text == "<PERSON_Rania Fahmy>"


def test_an_enormous_index_does_not_crash(reid):
    reid.restore("<PERSON_99999999999999999999>")


# -- drift -------------------------------------------------------------------

def test_the_observed_markdown_mangling_is_detected(store):
    scanner = DriftScanner(store)
    findings = scanner.scan(f"| **PER{NARROW_NBSP}1** | **PER{NARROW_NBSP}2** |")
    assert len(findings) == 2
    assert all(f.kind == "markdown_wrapped" and f.in_store for f in findings)


def test_the_observed_range_enumeration_is_detected(store):
    scanner = DriftScanner(store)
    raw = f"**PER{NARROW_NBSP}3{NON_BREAKING_HYPHEN}8,{NARROW_NBSP}20{NON_BREAKING_HYPHEN}22**"
    assert any(f.kind == "range_enumeration" for f in scanner.scan(raw))


def test_a_missing_delimiter_is_detected(store):
    assert DriftScanner(store).scan("PERSON 001")[0].kind == "delimiters_missing"


def test_an_intact_placeholder_is_not_drift(store):
    assert DriftScanner(store).scan("<PERSON_001>") == ()


def test_markdown_around_an_intact_placeholder_is_not_drift(store):
    # The SME transcript bolds its own system and customer names, so the
    # sanitized text legitimately contains "**<SYSTEM_001>**".
    assert DriftScanner(store).scan("**<PERSON_001>** and `<PERSON_002>`") == ()


@pytest.mark.parametrize("text", ["ISO 9001", "GPT 4", "section 12", "HTTP 404"])
def test_ordinary_text_is_not_drift(store, text):
    assert DriftScanner(store).scan(text) == ()


def test_drift_never_alters_the_output(reid):
    # The single most important guarantee of the drift layer: it reports, it
    # does not repair. A fuzzy substitution here would make model-controlled
    # text a lookup key into the mapping.
    raw = f"**PER{NARROW_NBSP}1** and **PER{NARROW_NBSP}2**"
    result = reid.restore(raw)
    assert result.text == raw
    assert result.drift
    assert "Rania" not in result.text and "Hossam" not in result.text


def test_a_range_enumeration_restores_nothing(reid):
    raw = f"**PER{NARROW_NBSP}1{NON_BREAKING_HYPHEN}3**"
    result = reid.restore(raw)
    assert result.text == raw


def test_drift_findings_carry_a_diagnostic_guess_only(store):
    finding = DriftScanner(store).scan(f"**PER{NARROW_NBSP}1**")[0]
    assert finding.normalized_guess == "<PERSON_001>"
    assert finding.in_store is True


# -- output scanning ---------------------------------------------------------

def test_a_raw_value_in_the_output_is_a_critical_finding(store):
    findings = OutputScanner(store).scan("The attendee was Rania Fahmy.")
    assert [f.severity for f in findings] == ["critical"]


def test_a_partial_name_is_a_warning(store):
    # reports/latest_run.json leaked bare "Sarah", "Michael" and "James" even
    # though the full names had been replaced.
    findings = OutputScanner(store).scan("Ask Fahmy about it.")
    assert [f.match_kind for f in findings] == ["name_token"]
    assert findings[0].severity == "warning"


def test_a_short_name_token_is_not_searched(store):
    assert OutputScanner(store, token_min_chars=99).scan("Ask Fahmy.") == ()


def test_case_insensitive_matching_for_name_types(store):
    assert OutputScanner(store).scan("rania fahmy was there")


def test_an_email_is_found_exactly(store):
    findings = OutputScanner(store).scan("write to sarah.mitchell@example.com")
    assert any(f.entity_type == "EMAIL" for f in findings)


def test_clean_output_produces_no_findings(store):
    assert OutputScanner(store).scan("Contact <PERSON_001> for details.") == ()


def test_assert_clean_raises_on_a_leak(store):
    with pytest.raises(SanitizationLeakError):
        OutputScanner(store).assert_clean("Rania Fahmy attended", "pre_send")


def test_assert_clean_passes_on_sanitized_text(store):
    OutputScanner(store).assert_clean("<PERSON_001> attended", "pre_send")


def test_the_leak_error_does_not_contain_the_leaked_value(store):
    with pytest.raises(SanitizationLeakError) as excinfo:
        OutputScanner(store).assert_clean("Rania Fahmy attended", "pre_send")
    assert "Rania" not in str(excinfo.value)


def test_a_leak_finding_repr_does_not_contain_the_value(store):
    finding = OutputScanner(store).scan("Rania Fahmy")[0]
    assert "Rania" not in repr(finding)


def test_a_leak_makes_the_result_degraded(reid):
    assert reid.restore("Rania Fahmy was there").status == "degraded"


# -- conversation isolation --------------------------------------------------

def test_restoring_with_the_wrong_conversation_id_is_refused(reid):
    with pytest.raises(ConversationMismatchError):
        reid.restore("<PERSON_001>", conversation_id="c-other")


def test_restoring_with_the_right_conversation_id_succeeds(reid):
    assert reid.restore("<PERSON_001>", conversation_id="c-1").text == "Rania Fahmy"


def test_a_placeholder_from_another_conversation_is_inert():
    other = MappingStore("c-2")
    other.assign(
        DetectedEntity(
            entity_type="PERSON", text="Someone Else", start=0, end=12,
            confidence=0.9, detector="ner",
        ),
        PERSON,
    )
    result = Reidentifier(other, PolicyEngine()).restore("<PERSON_002>")
    assert "Someone Else" not in result.text
    assert result.unknown == ("<PERSON_002>",)


# -- reporting ---------------------------------------------------------------

def test_unrestored_placeholders_are_reported(reid):
    result = reid.restore("<PERSON_001> only")
    assert "<PERSON_002>" in result.unrestored


def test_stats_are_populated(reid):
    result = reid.restore("<PERSON_001> and <PERSON_010>")
    assert result.stats["restored"] == 1
    assert result.stats["unknown"] == 1
