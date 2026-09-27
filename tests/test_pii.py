"""Regression tests, written against the failures in the pod meeting run."""

from __future__ import annotations

import re

import pytest

from pii import PIIMiddleware, Span, SpanSet, apply_spans, extract_roster, propagate_names
from pii.chunking import iter_windows
from pii.detector import is_plausible
from pii.middleware import audit, unify_labels
from pii.patterns import detect_patterns


def _card_span(text: str):
    return next(
        (s for s in detect_patterns(text) if s.label == "CREDIT_CARD"),
        None,
    )
from pii.vault import PseudonymVault, link_person_identities, restore

TRANSCRIPT = """Ahmed Farid   0:31
Content Creation is fine.

Rania Fahmy   0:54
I don't know.

Lamia Aly   1:02
Reach me on lamia.aly@example.com or +20 100 123 4567.

Ahmed Farid   1:10
Lamia said Cortana is broken.

Rania Fahmy   2:00
Badri will follow up with Farid.
"""


class TestSpans:
    def test_replacement_is_offset_based(self):
        """The original bug: replacing 'Co' globally corrupted 'Content'."""
        text = "Co met Content and Cortana."
        span = Span(start=0, end=2, label="PERSON", text="Co")
        assert apply_spans(text, [(span, "{{PERSON_1}}")]) == (
            "{{PERSON_1}} met Content and Cortana."
        )

    def test_longest_span_wins_an_overlap(self):
        spans = SpanSet()
        spans.add(Span(0, 5, "PERSON", "Lamia", source="sweep"))
        spans.add(Span(0, 9, "PERSON", "Lamia Aly", source="model"))
        resolved = spans.resolve()
        assert [span.text for span in resolved] == ["Lamia Aly"]

    def test_pattern_beats_a_longer_model_span(self):
        text = "lamia.aly@example.com"
        spans = SpanSet()
        spans.add(Span(0, len(text), "ORG", text, source="model"))
        spans.add(Span(0, len(text), "EMAIL", text, source="pattern"))
        assert spans.resolve()[0].label == "EMAIL"

    def test_resolved_spans_never_overlap(self):
        spans = SpanSet()
        spans.add(Span(0, 10, "PERSON", "a" * 10, source="model"))
        spans.add(Span(5, 15, "ORG", "b" * 10, source="model"))
        resolved = spans.resolve()
        assert len(resolved) == 1


class TestChunking:
    def test_long_text_is_fully_covered(self):
        """The original bug: everything past 512 tokens was never scanned."""
        text = "\n".join(f"line {index} with some words" for index in range(500))
        windows = iter_windows(text, max_chars=400, overlap_chars=80)
        assert windows[0].offset == 0
        assert windows[-1].offset + len(windows[-1].text) == len(text)

    def test_windows_overlap(self):
        text = "\n".join(f"line {index}" for index in range(200))
        windows = iter_windows(text, max_chars=300, overlap_chars=100)
        for earlier, later in zip(windows, windows[1:]):
            assert later.offset < earlier.offset + len(earlier.text)

    def test_short_text_is_one_window(self):
        assert len(iter_windows("hello", max_chars=100)) == 1

    def test_empty_text(self):
        assert iter_windows("") == []


class TestPatterns:
    @pytest.mark.parametrize(
        ("text", "label"),
        [
            ("write to sam.d@example.co.uk now", "EMAIL"),
            ("call +20 100 123 4567 today", "PHONE"),
            ("ssn 123-45-6789 on file", "SSN"),
            ("see https://example.com/x for more", "URL"),
            ("host 192.168.1.44 is down", "IP_ADDRESS"),
            ("card 4111 1111 1111 1111 expires", "CREDIT_CARD"),
        ],
    )
    def test_structured_identifiers(self, text, label):
        assert label in {span.label for span in detect_patterns(text)}

    def test_checksum_failure_still_redacts(self):
        """The regression that started the refactor.

        A Luhn gate is why 4532-0192-8834-5610 leaked. A card with a typo is
        still a card, so the checksum now grades confidence instead of vetoing.
        """
        assert _card_span("card 4111 1111 1111 1112 here") is not None

    def test_weaker_evidence_scores_lower(self):
        """Confidence still tracks the evidence, it just no longer gates."""
        shape_only = _card_span("9111 1111 1111 1119")
        corroborated = _card_span("card 4111 1111 1111 1111 here")
        assert shape_only is not None and corroborated is not None
        assert shape_only.score < corroborated.score

    def test_the_card_that_leaked_is_now_caught(self):
        span = _card_span("The card number is 4532-0192-8834-5610, expires 08/29")
        assert span is not None and span.text == "4532-0192-8834-5610"

    def test_bare_contextless_digit_run_is_not_a_card(self):
        """The one shape that must stay below threshold."""
        assert _card_span("reference 1234567890123456 follows") is None

    def test_transcript_timecodes_are_not_phone_numbers(self):
        assert detect_patterns("Ahmed Farid   0:31\n30m 37s\n") == []


class TestRoster:
    def test_speakers_are_extracted(self):
        assert set(extract_roster(TRANSCRIPT)) == {"Ahmed Farid", "Rania Fahmy"}

    def test_single_turn_speaker_is_ignored(self):
        assert "Lamia Aly" not in extract_roster(TRANSCRIPT)

    def test_shorthand_mentions_are_propagated(self):
        """The original bug: 'Lamia' survived 57 times in plaintext."""
        spans = propagate_names(TRANSCRIPT, ["Lamia Aly"])
        assert {span.text for span in spans} >= {"Lamia Aly", "Lamia"}

    def test_variants_share_one_identity(self):
        spans = propagate_names(TRANSCRIPT, ["Ahmed Farid"])
        assert len({span.identity for span in spans}) == 1

    def test_lowercase_common_words_are_left_alone(self):
        spans = propagate_names("the will of the people", ["Will Smith"])
        assert spans == []

    def test_timecode_first_format(self):
        """Exporters disagree on speaker markup; both shapes must work."""
        text = "**09:00 - Ahmed Hassan:**\nHi.\n\n**09:05 - Ahmed Hassan:**\nBye.\n"
        assert extract_roster(text) == ["Ahmed Hassan"]

    def test_plain_speaker_label_format(self):
        text = "Sarah Mitchell:\nHi.\n\nSarah Mitchell:\nBye.\n"
        assert extract_roster(text) == ["Sarah Mitchell"]

    def test_section_headings_are_not_speakers(self):
        assert extract_roster("For example:\nx\n\nFor example:\ny\n") == []

    def test_name_particles_are_allowed(self):
        text = "Ana de Souza:\nHi.\n\nAna de Souza:\nBye.\n"
        assert extract_roster(text) == ["Ana de Souza"]


class TestPlausibility:
    @pytest.mark.parametrize("surface", ["phone", "local", "home", "L.", "a"])
    def test_implausible_names_rejected(self, surface):
        assert not is_plausible("PERSON", surface)

    @pytest.mark.parametrize("surface", ["Lamia Aly", "Abdulrahman", "Rania Fahmy"])
    def test_real_names_accepted(self, surface):
        assert is_plausible("PERSON", surface)

    def test_clauses_are_rejected(self):
        assert not is_plausible("LOCATION", "Noha, la front end")

    def test_structured_types_are_left_to_the_regex_layer(self):
        assert not is_plausible("EMAIL", "a@b.com")


class TestLabelUnification:
    def test_same_surface_form_gets_one_label(self):
        """The original bug: 'Lamya' was a person here and a location there."""
        spans = [
            Span(0, 5, "LOCATION", "Lamya", score=0.9, source="model"),
            Span(10, 15, "PERSON", "Lamya", score=0.9, source="model"),
        ]
        assert len({span.label for span in unify_labels(spans)}) == 1

    def test_ties_break_toward_person(self):
        spans = [
            Span(0, 5, "LOCATION", "Lamya", score=0.9, source="model"),
            Span(10, 15, "PERSON", "Lamya", score=0.9, source="model"),
        ]
        assert unify_labels(spans)[0].label == "PERSON"


class TestVault:
    def test_one_placeholder_per_entity(self):
        vault = PseudonymVault()
        first = vault.placeholder_for(Span(0, 11, "PERSON", "Ahmed Farid"))
        second = vault.placeholder_for(Span(20, 31, "PERSON", "Ahmed Farid"))
        assert first == second

    def test_longest_surface_form_is_canonical(self):
        vault = PseudonymVault()
        identity = "PERSON:ahmed farid"
        vault.placeholder_for(Span(0, 5, "PERSON", "Farid", identity=identity))
        placeholder = vault.placeholder_for(
            Span(10, 21, "PERSON", "Ahmed Farid", identity=identity)
        )
        assert vault.mapping[placeholder] == "Ahmed Farid"

    def test_unambiguous_surname_links_to_full_name(self):
        spans = [
            Span(0, 11, "PERSON", "Ahmed Farid", source="model"),
            Span(20, 25, "PERSON", "Farid", source="model"),
        ]
        assert len({span.identity for span in link_person_identities(spans)}) == 1

    def test_ambiguous_first_name_stays_separate(self):
        """'Ahmed' belongs to three people, so it must not merge into one."""
        spans = [
            Span(0, 11, "PERSON", "Ahmed Farid", source="model"),
            Span(20, 31, "PERSON", "Ahmed Maher", source="model"),
            Span(40, 45, "PERSON", "Ahmed", source="model"),
        ]
        identities = {span.identity for span in link_person_identities(spans)}
        assert len(identities) == 3


class TestRestore:
    def test_round_trip(self):
        mapping = {"{{PERSON_1}}": "Ahmed Farid"}
        assert restore("Hi {{PERSON_1}}.", mapping) == "Hi Ahmed Farid."

    @pytest.mark.parametrize(
        "echoed", ["{{PERSON_1}}", "[PERSON_1]", "<PERSON_1>", "[[PERSON_1]]", "{{ PERSON_1 }}"]
    )
    def test_tolerates_reformatted_placeholders(self, echoed):
        """LLMs reformat brackets; a placeholder must still restore."""
        assert restore(echoed, {"{{PERSON_1}}": "Ahmed Farid"}) == "Ahmed Farid"

    def test_unknown_placeholder_is_left_alone(self):
        assert restore("{{PERSON_9}}", {"{{PERSON_1}}": "X"}) == "{{PERSON_9}}"


class TestAudit:
    def test_surviving_value_is_a_high_severity_leak(self):
        leaks = audit("Lamia is here", {"{{PERSON_1}}": {"Lamia"}}, [])
        assert leaks[0]["severity"] == "high"

    def test_differently_cased_word_is_only_a_note(self):
        """'composer' the word is not a leak of 'Composer' the entity.

        The document has to say so: the grade now depends on whether the text
        itself uses the word in lowercase prose. Without that evidence this
        fails safe to high, which is what stopped "Kwame" matching
        "KWAME MENSAH" being waved through as a note.
        """
        from pii.context import DocumentContext

        text = "a composer wrote it"
        leaks = audit(text, {"{{PERSON_1}}": {"Composer"}}, [], DocumentContext.build(text))
        assert [leak["severity"] for leak in leaks] == ["low"]

    def test_case_variant_without_document_evidence_fails_safe(self):
        leaks = audit("a composer wrote it", {"{{PERSON_1}}": {"Composer"}}, [])
        assert [leak["severity"] for leak in leaks] == ["high"]

    def test_clean_text_has_no_leaks(self):
        assert audit("{{PERSON_1}} is here", {"{{PERSON_1}}": {"Lamia"}}, []) == []


@pytest.fixture(scope="module")
def middleware():
    return PIIMiddleware()


@pytest.fixture(scope="module")
def result(middleware):
    return middleware.analyze(TRANSCRIPT)


@pytest.mark.slow
class TestEndToEnd:
    """Exercises the real models; slow, but this is the behaviour that matters."""

    def test_verification_passes(self, result):
        assert result.is_clean, result.high_severity_leaks

    def test_no_speaker_name_survives(self, result):
        for name in ("Ahmed Farid", "Rania Fahmy", "Lamia Aly", "Lamia"):
            assert name not in result.sanitized

    def test_no_placeholder_lands_mid_word(self, result):
        """Guards the corruption bug that produced '<PER_11>ntent'."""
        assert not re.search(r"\}\}\w", result.sanitized)
        assert not re.search(r"\w\{\{", result.sanitized)

    def test_allowlisted_product_is_kept(self, result):
        """'Cortana' is a product, not a person."""
        assert "Cortana" in result.sanitized

    def test_contact_details_are_removed(self, result):
        assert "lamia.aly@example.com" not in result.sanitized
        assert "+20 100 123 4567" not in result.sanitized

    def test_placeholders_restore_to_originals(self, result, middleware):
        restored = middleware.restore(result.sanitized, result.mapping)
        assert "Ahmed Farid" in restored
        assert "lamia.aly@example.com" in restored

    def test_whole_document_is_scanned(self, middleware):
        """Guards the 512-token truncation that skipped 87% of the input."""
        padding = "\n".join(f"Filler line {index} of the meeting." for index in range(400))
        result = middleware.analyze(f"{padding}\n\nHossam Badri joined at the end.")
        assert "Hossam Badri" not in result.sanitized
