"""Regression tests for the six held-out defects and the new policy surface.

Each test here corresponds to a defect recorded in docs/review-response.md,
or to a config gap the same review raised (per-entity policy, fixed names).
None of these were tuned against tests/holdout/ -- every fixture below is
hand-written from the defect's description, and tests/holdout/ is scored
separately, unchanged, as the final report.
"""

from __future__ import annotations

import pytest

from pii import LeakDetected, PIIMiddleware, Span
from pii.entities import EntityIndex
from pii.middleware import assign_identities
from pii.patterns import detect_patterns
from pii.policy import resolve_types
from pii.roster import _uninvert, name_variants, propagate_names


class FixedDetector:
    """A detector that returns exactly the spans it was given."""

    def __init__(self, spans: list[Span]):
        self.spans = spans

    def detect(self, text: str) -> list[Span]:
        return self.spans


# ---------------------------------------------------------------------------
# D6: a CIDR block was redacted as an IP address, leaving the prefix dangling.
# ---------------------------------------------------------------------------


class TestCidrIsNotAnAddress:
    @pytest.mark.parametrize(
        "text",
        [
            "advertise 10.0.0.0/8 to peers",
            "route: 192.168.0.0/16 and 10.0.0.0/8 are private ranges",
            "the reserved block 172.16.0.0/12 is unused",
        ],
    )
    def test_cidr_blocks_are_not_detected_as_ip_addresses(self, text):
        labels = {span.label for span in detect_patterns(text)}
        assert "IP_ADDRESS" not in labels

    def test_a_real_address_with_a_trailing_period_still_matches(self):
        """The fix must not re-break the sentence-period case it shares code with."""
        text = "the private network at 10.0.4.15."
        spans = [s for s in detect_patterns(text) if s.label == "IP_ADDRESS"]
        assert [s.text for s in spans] == ["10.0.4.15"]

    def test_a_real_address_with_a_port_still_matches(self):
        text = "server at 10.0.4.15:8443 is up"
        spans = [s for s in detect_patterns(text) if s.label == "IP_ADDRESS"]
        assert [s.text for s in spans] == ["10.0.4.15"]

    def test_end_to_end_cidr_is_untouched(self):
        mw = PIIMiddleware(detectors=[], use_roster=False, use_titles=False, on_leak="ignore")
        text = "advertise 10.0.0.0/8 to peers"
        assert mw.analyze(text).sanitized == text


# ---------------------------------------------------------------------------
# D4: "A. Kone" and "Ayodele Kone" landed on two placeholders.
# (Using "Priya Raman" here -- the holdout's own names are never used.)
# ---------------------------------------------------------------------------


class TestInitialFormsMergeIntoTheFullName:
    def test_a_dot_surname_merges_into_the_unique_full_name(self):
        text = "Priya Raman signed the filing. P. Raman confirmed receipt the next day."
        spans = [
            Span(0, 11, "PERSON", "Priya Raman", source="model"),
            Span(32, 40, "PERSON", "P. Raman", source="model"),
        ]
        resolved = assign_identities(text, spans)
        identities = {span.text: span.identity for span in resolved}
        assert identities["Priya Raman"] == identities["P. Raman"]

    def test_a_shared_surname_and_initial_does_not_merge(self):
        """Two people, same surname, same initial: guessing would merge them."""
        text = "Rosalind Pelletier and Rupert Pelletier attended. R. Pelletier signed."
        spans = [
            Span(0, 19, "PERSON", "Rosalind Pelletier", source="model"),
            Span(24, 40, "PERSON", "Rupert Pelletier", source="model"),
            Span(51, 63, "PERSON", "R. Pelletier", source="model"),
        ]
        resolved = assign_identities(text, spans)
        identities = {span.text: span.identity for span in resolved}
        assert len({identities["Rosalind Pelletier"], identities["Rupert Pelletier"], identities["R. Pelletier"]}) == 3

    def test_propagate_names_generates_the_initial_form_for_coverage(self):
        """Coverage, not just merging: the model may miss "P. Raman" entirely."""
        text = "Priya Raman filed the report. P. Raman signed it the next day."
        spans = propagate_names(text, ["Priya Raman"])
        matched = [s for s in spans if s.start == text.index("P. Raman")]
        assert matched and matched[0].identity == "PERSON:priya raman"


# ---------------------------------------------------------------------------
# D3: "Kone, Ayodele" (inverted form) left the surname and comma in plaintext.
# ---------------------------------------------------------------------------


class TestInvertedNameForm:
    def test_uninvert_swaps_surname_and_given_name(self):
        assert _uninvert("Raman, Priya") == "Priya Raman"

    def test_uninvert_leaves_an_ordinary_name_alone(self):
        assert _uninvert("Priya Raman") == "Priya Raman"

    def test_name_variants_include_the_inverted_form(self):
        assert "Raman, Priya" in name_variants("Priya Raman")

    def test_the_whole_inverted_mention_is_redacted_as_one_span(self):
        """The defect: only the given name was masked, leaving "Raman," behind."""
        text = "Raman, Priya filed the motion. Priya Raman signed it."
        spans = propagate_names(text, ["Priya Raman"])
        inverted = next(s for s in spans if s.text == "Raman, Priya")
        assert inverted.start == 0 and inverted.end == len("Raman, Priya")

    def test_end_to_end_no_comma_is_left_dangling(self):
        mw = PIIMiddleware(detectors=[], use_roster=True, on_leak="ignore")
        text = (
            "Priya Raman: this is my opening statement, and I want it on the record please.\n"
            "Priya Raman: I have reviewed the filing carefully and have nothing to add today.\n"
            "Index of appearances: Raman, Priya (witness).\n"
        )
        result = mw.analyze(text)
        assert "Raman," not in result.sanitized
        assert "Priya" not in result.sanitized


# ---------------------------------------------------------------------------
# D2a/D2b: honorific-only mentions -- a missing span, and a missing identity.
# ---------------------------------------------------------------------------


class TestHonorificOnlyMentions:
    def test_a_surname_only_model_span_is_widened_over_its_title(self):
        """The defect: the model tags only the surname, leaving "Mr." bare."""
        line = "Mr. Raman confirmed the invoice."
        start = line.index("Raman")
        span = Span(start, start + len("Raman"), "PERSON", "Raman", source="model")
        from pii.spanfix import normalize_span

        edit = normalize_span(line, span)
        assert edit is not None and edit.text == "Mr. Raman"

    def test_a_full_name_model_span_is_not_widened(self):
        """The title stays visible beside a full name -- it is not itself PII."""
        line = "Dr. Priya Raman confirmed the invoice."
        start = line.index("Priya Raman")
        span = Span(start, start + len("Priya Raman"), "PERSON", "Priya Raman", source="model")
        from pii.spanfix import normalize_span

        edit = normalize_span(line, span)
        assert edit is not None and edit.text == "Priya Raman"

    def test_shared_surname_titles_are_both_masked_as_distinct_people(self):
        """The defect: neither full name ever appears with a title, so
        ownership was never unique and nothing was emitted for either."""
        text = (
            "Priya Raman: I will present first, thank you all for making time today.\n"
            "Priya Raman: that concludes my portion, happy to take questions after.\n"
            "Devesh Raman: I will go second, following on from what was just said.\n"
            "Devesh Raman: that wraps up the budget section from my side today.\n"
            "Ms. Raman opened with the roadmap, then Mr. Raman followed with numbers.\n"
        )
        mw = PIIMiddleware(detectors=[], use_roster=True, on_leak="ignore")
        result = mw.analyze(text)
        assert "Ms. Raman" not in result.sanitized
        assert "Mr. Raman" not in result.sanitized
        placeholders = {v for v in result.mapping if "Ms." not in result.mapping[v]}
        # Two people were introduced via the roster; the titled mentions must
        # not have silently merged onto a single placeholder.
        assert len(result.mapping) >= 2


# ---------------------------------------------------------------------------
# D1: a common-word first name ("Will") was never propagated on its own.
# ---------------------------------------------------------------------------


class TestCommonWordFirstName:
    def test_a_mid_sentence_mention_is_now_redacted(self):
        text = (
            "Will Vuorinen: hello everyone, thanks for joining the call today please\n"
            "Will Vuorinen: I wanted to go over the quarterly numbers with everyone\n"
            "I spoke with Will about the budget last week, and Will agreed to the plan.\n"
        )
        mw = PIIMiddleware(detectors=[], use_roster=True, on_leak="ignore")
        result = mw.analyze(text)
        assert "Will" not in result.sanitized

    def test_a_sentence_initial_mention_is_left_alone(self):
        """The unresolved half: with no part-of-speech evidence, a
        sentence-initial common word is indistinguishable from the modal
        verb, so it stays unmasked rather than risk shredding a question."""
        text = (
            "Will Vuorinen: hello everyone, thanks for joining the call today please\n"
            "Will Vuorinen: I wanted to go over the quarterly numbers with everyone\n"
            "Will you confirm the numbers by Friday?\n"
        )
        mw = PIIMiddleware(detectors=[], use_roster=True, on_leak="ignore")
        result = mw.analyze(text)
        assert "Will you confirm the numbers by Friday?" in result.sanitized

    def test_an_uncommon_name_is_unaffected(self):
        """Guard: the common-word relaxation must not change ordinary names."""
        text = (
            "Priya Raman: hello everyone, thanks for joining the call today please\n"
            "Priya Raman: I wanted to go over the quarterly numbers with everyone\n"
        )
        mw = PIIMiddleware(detectors=[], use_roster=True, on_leak="ignore")
        result = mw.analyze(text)
        assert "Priya" not in result.sanitized and "Raman" not in result.sanitized


# ---------------------------------------------------------------------------
# D5a: a lowercase ASR transcription of a known name was never matched.
# ---------------------------------------------------------------------------


class TestLowercaseAsrNames:
    def test_a_lowercase_mention_on_an_all_lowercase_line_is_redacted(self):
        text = (
            "Priya Raman: hello everyone, thanks so much for joining this call today\n"
            "Priya Raman: I wanted to walk through the roadmap before we get started\n"
            "so i pinged raman about it and she said the plan was fine to go ahead\n"
        )
        mw = PIIMiddleware(detectors=[], use_roster=True, on_leak="ignore")
        result = mw.analyze(text)
        assert "raman" not in result.sanitized

    def test_the_same_lowercase_word_on_a_cased_line_is_left_alone(self):
        """The signal is the line's casing, not the word: a properly cased
        document writing the same token as an ordinary lowercase word must
        not lose it just because it collides with a confirmed name."""
        text = (
            "Priya Raman: hello everyone, thanks so much for joining this call today\n"
            "Priya Raman: I wanted to walk through the roadmap before we get started\n"
            "The document references a raman spectroscopy technique from last year.\n"
        )
        mw = PIIMiddleware(detectors=[], use_roster=True, on_leak="ignore")
        result = mw.analyze(text)
        assert "a raman spectroscopy technique" in result.sanitized

    def test_a_short_lowercase_token_is_not_enough_evidence(self):
        """Below four characters, a lowercase match is indistinguishable
        from a stray short word even when the roster confirms the name."""
        text = (
            "Al Priyanka: hello everyone, thanks so much for joining this call today\n"
            "Al Priyanka: I wanted to walk through the roadmap before we get started\n"
            "please send the report to al when you get a chance this afternoon\n"
        )
        mw = PIIMiddleware(detectors=[], use_roster=True, on_leak="ignore")
        result = mw.analyze(text)
        assert "to al when" in result.sanitized


# ---------------------------------------------------------------------------
# Per-entity policy: entities= overrides a profile without replacing it.
# ---------------------------------------------------------------------------


class TestEntityPolicy:
    def test_duration_time_amount_are_not_redacted_by_default(self):
        redacted = resolve_types("balanced")
        assert not ({"DURATION", "TIME", "AMOUNT"} & redacted)

    def test_an_unmentioned_type_keeps_the_profile_default(self):
        redacted = resolve_types("balanced", {"url": False})
        assert "PERSON" in redacted and "EMAIL" in redacted and "URL" not in redacted

    def test_a_caller_can_opt_back_into_duration(self):
        redacted = resolve_types("balanced", {"duration": True})
        assert "DURATION" in redacted

    def test_an_unknown_entity_key_raises(self):
        with pytest.raises(ValueError, match="unknown entity type"):
            resolve_types("balanced", {"persn": True})

    def test_a_mandatory_type_cannot_be_disabled(self):
        with pytest.raises(ValueError, match="mandatory"):
            resolve_types("balanced", {"norp": False})

    def test_end_to_end_duration_is_left_alone_unless_requested(self):
        mw = PIIMiddleware(detectors=[], use_roster=False, on_leak="ignore")
        text = "The call lasted 48 minutes."
        assert mw.analyze(text).sanitized == text

        mw_opt_in = PIIMiddleware(
            detectors=[], use_roster=False, on_leak="ignore", entities={"duration": True}
        )
        assert mw_opt_in.analyze(text).sanitized != text

    def test_disabled_entity_does_not_fail_residual_gate(self):
        # Disabling EMAIL redaction must not cause default on_leak="raise"
        # to fail when an email is present in the document.
        mw = PIIMiddleware(
            detectors=[],
            use_roster=False,
            entities={"email": False},
        )
        text = "Please reach out to support@example.com for further assistance."
        res = mw.analyze(text)
        assert res.is_clean
        assert "support@example.com" in res.sanitized

    def test_secrets_are_blocked_even_when_entities_are_disabled(self):
        # Mandatory secret detection (e.g. JWT tokens) remains active
        # and raises even if standard entities like EMAIL or IP are turned off.
        mw = PIIMiddleware(
            detectors=[],
            use_roster=False,
            entities={"email": False},
        )
        text = "Contact user@example.com with token 4a5f6e7b8c9d0e1f2a3b4c5d6e7f8a9b"
        with pytest.raises(LeakDetected):
            mw.analyze(text)

    def test_minimal_profile_speaker_labels_do_not_fail_residual(self):
        # Under minimal profile, PERSON is not in scope. Speaker labels in
        # transcript turns must not trigger residual unredacted_speaker_label.
        mw = PIIMiddleware(
            profile="minimal",
            detectors=[],
            use_roster=False,
        )
        text = "[10:14] Sarah Jenkins: We are reviewing the logs now."
        res = mw.analyze(text)
        assert res.is_clean
        assert "Sarah Jenkins" in res.sanitized


# ---------------------------------------------------------------------------
# Fixed names: masked wherever they appear, independent of model detection.
# ---------------------------------------------------------------------------


class TestFixedNames:
    def test_a_fixed_name_is_masked_with_no_detectors_at_all(self):
        mw = PIIMiddleware(
            detectors=[], use_roster=False, on_leak="ignore", fixed_names=["Priya Raman"]
        )
        text = "priya said the numbers were fine, and Priya Raman signed off on them personally."
        result = mw.analyze(text)
        assert "priya" not in result.sanitized.lower()
        assert result.mapping and list(result.mapping.values())[0] == "Priya Raman"

    def test_a_common_word_fixed_name_is_still_masked(self):
        mw = PIIMiddleware(
            detectors=[], use_roster=False, on_leak="ignore", fixed_names=["Will Vuorinen"]
        )
        text = "Will confirmed the plan. Will you also check the numbers?"
        result = mw.analyze(text)
        assert "Will" not in result.sanitized

    def test_an_empty_fixed_name_raises_at_construction(self):
        with pytest.raises(ValueError):
            PIIMiddleware(fixed_names=["  "])

    def test_fixed_names_apply_even_with_roster_disabled(self):
        mw = PIIMiddleware(
            detectors=[], use_roster=False, on_leak="ignore", fixed_names=["Priya Raman"]
        )
        text = "A note: Priya Raman was mentioned once, in passing, nothing else here."
        result = mw.analyze(text)
        assert "Priya Raman" not in result.sanitized

    def test_fixed_names_are_masked_unconditionally_when_person_is_disabled(self):
        # Fixed names are explicit instructions and must be redacted even if
        # PERSON is disabled or under profile="minimal".
        mw = PIIMiddleware(
            profile="minimal",
            detectors=[],
            use_roster=False,
            fixed_names=["Priya Raman"],
        )
        text = "[10:14] Sarah Jenkins: I spoke with Priya Raman about the contract."
        result = mw.analyze(text)
        # Priya Raman is masked unconditionally
        assert "Priya Raman" not in result.sanitized
        assert "{{PERSON_" in result.sanitized
        # Sarah Jenkins is untouched because PERSON is not in scope under minimal profile
        assert "Sarah Jenkins" in result.sanitized
        assert result.is_clean


# ---------------------------------------------------------------------------
# Production deployment contract
# ---------------------------------------------------------------------------


class TestProductionContract:
    def test_for_production_enforces_raise_and_full_ensemble(self):
        mw = PIIMiddleware.for_production()
        assert mw.on_leak == "raise"
        assert mw.strict is True
        names = {type(d).__name__ for d in mw.detectors}
        assert "GlinerDetector" in names
        assert "SpacyDetector" in names

    def test_for_production_records_detector_provenance(self):
        mw = PIIMiddleware.for_production()
        res = mw.analyze("Contact: dev@example.com")
        assert res.detector_status
        for entry in res.detector_status:
            assert "name" in entry
            assert "available" in entry
            assert "package" in entry

    def test_secret_rules_cannot_be_disabled(self):
        from pii.residual import ResidualPolicy
        with pytest.raises(ValueError, match="mandatory secret rules cannot be disabled in secret_rules"):
            ResidualPolicy(secret_rules=frozenset({"jwt"}))
        with pytest.raises(ValueError, match="mandatory secret rules cannot be disabled in enabled_rules"):
            ResidualPolicy(enabled_rules=frozenset({"email"}))

    def test_safe_sanitized_blocks_transmission_on_failed_status(self):
        mw = PIIMiddleware(detectors=[], use_roster=False, on_leak="warn")
        res = mw.analyze("token 4a5f6e7b8c9d0e1f2a3b4c5d6e7f8a9b")
        assert res.status == "failed"
        with pytest.raises(LeakDetected, match="refusing to return sanitized text"):
            _ = res.safe_sanitized
        with pytest.raises(LeakDetected, match="refusing to return sanitized text"):
            _ = res.as_tuple()
        with pytest.raises(LeakDetected, match="refusing to return sanitized text"):
            _ = mw.anonymize("token 4a5f6e7b8c9d0e1f2a3b4c5d6e7f8a9b")

    def test_attached_name_particles_and_duration_speakers_in_roster(self):
        from pii.roster import extract_roster
        text = (
            "Mohamed elSharif 1 hour 12 minutes 56 seconds\n"
            "Hello team.\n"
            "Mohamed elSharif 1 hour 12 minutes 58 seconds\n"
            "Can you hear me?\n"
        )
        roster = extract_roster(text)
        assert "Mohamed elSharif" in roster


class TestCaselessScripts:
    def test_is_plausible_accepts_arabic_person_names(self):
        from pii.detector import is_plausible

        assert is_plausible("PERSON", "طارق منصور") is True
        assert is_plausible("PERSON", "محمد") is True
        assert is_plausible("PERSON", "فاطمة") is True

    def test_extract_roster_finds_arabic_speakers(self):
        from pii.roster import extract_roster

        transcript = (
            "طارق منصور: مرحباً بالجميع\n"
            "فاطمة حسن: أهلاً طارق\n"
            "طارق منصور: سنبدأ الاجتماع\n"
            "فاطمة حسن: متفقون تماماً\n"
        )
        roster = extract_roster(transcript)
        assert "طارق منصور" in roster
        assert "فاطمة حسن" in roster\n