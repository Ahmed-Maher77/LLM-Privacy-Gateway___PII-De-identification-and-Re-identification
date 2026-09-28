"""Does the redactor generalise, or has it just memorised the last document?

The rest of the suite asserts literals from specific transcripts. That is how
three rounds of fixes each repaired the newest document and regressed an older
one. These tests score the whole labelled corpus instead, and gate on the two
numbers that matter: no leaks, and no precision regression.
"""

from __future__ import annotations

import json
import re
import unicodedata

import pytest

from pii import PIIMiddleware
from pii.context import DocumentContext
from pii.middleware import _mark_eponymous, audit
from pii.patterns import DATE_PATTERN, detect_patterns
from pii.spanfix import _is_acronym_or_code, normalize_span, normalize_spans
from pii.spans import Span
from pii.vault import _canonical_rank

from tools.evaluate import BASELINE_PATH, load_fixtures, score_document


@pytest.fixture(scope="module")
def middleware():
    return PIIMiddleware(on_leak="warn")


@pytest.fixture(scope="module")
def scores(middleware):
    return [
        score_document(name, source, expected, middleware)
        for name, source, expected in load_fixtures()
    ]


@pytest.mark.slow
class TestCorpus:
    def test_no_leaks_anywhere(self, scores):
        """A leak is unrecoverable, so this is the one hard gate."""
        leaking = {s.name: s.leaks for s in scores if s.leaks}
        assert not leaking, leaking

    def test_no_precision_regression(self, scores):
        """Over-redaction is what quietly degraded while recall was chased."""
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        regressions = {
            s.name: (baseline["per_document"][s.name]["precision"], s.precision)
            for s in scores
            if s.name in baseline["per_document"]
            and s.precision < baseline["per_document"][s.name]["precision"] - 1e-9
        }
        assert not regressions, regressions

    def test_baseline_covers_every_fixture(self, scores):
        """A fixture the baseline has never seen is silently exempt above.

        `test_no_precision_regression` only checks documents present in
        `baseline["per_document"]` -- it was reading the corpus this way
        when the twelve `prod_*` fixtures were added and absent from the
        baseline, and adding a fixture opted it out of the precision gate
        instead of failing until `--baseline` was rerun. This closes that
        hole from the other side: every fixture the corpus loader finds must
        already be in the baseline, or this fails loudly and says which one
        is missing, rather than quietly measuring nothing for it.
        """
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        missing = sorted(s.name for s in scores if s.name not in baseline["per_document"])
        assert not missing, (
            f"{missing} not in baseline.json -- run `uv run python tools/evaluate.py "
            "--baseline` after adding a fixture"
        )

    def test_one_placeholder_per_entity(self, scores):
        """The Oncology cascade bound two real values to one placeholder."""
        split = {s.name: s.split_entities for s in scores if s.split_entities}
        assert not split, split

    def test_documents_are_not_damaged(self, scores):
        broken = {s.name: s.integrity for s in scores if s.integrity}
        assert not broken, broken

    def test_zero_pii_control_is_untouched(self, middleware):
        """The control must come back byte-identical. It used to invent a
        person out of 'Three workers'."""
        source = next(
            src for name, src, _ in load_fixtures() if name == "scenario_10_no_pii_control"
        )
        assert middleware.analyze(source).sanitized == source


class TestSpanNormalisation:
    """Boundary drift was the most common defect and the most expensive one."""

    @pytest.mark.parametrize(
        ("sentence", "span", "expected"),
        [
            ("the issue affects the Dubai warehouse.", "Dubai warehouse", "Dubai"),
            ("the Shalaby project starts Monday.", "Shalaby project", "Shalaby"),
            ("09:06 - Ahmed Hassan: hello", "06 - Ahmed Hassan", "Ahmed Hassan"),
            ("that Blue Harbor's agent was", "Blue Harbor's", "Blue Harbor"),
            ("Location: Remote (Zoom Bridge)", "Remote (Zoom Bridge", "Remote"),
        ],
    )
    def test_edges_are_tightened(self, sentence, span, expected):
        start = sentence.index(span)
        edit = normalize_span(
            sentence, Span(start, start + len(span), "PERSON", span, source="model")
        )
        assert edit is not None and edit.text == expected

    def test_column_gap_is_not_part_of_a_name(self):
        """The cascade: a seven-space column gap made "Oncology" part of a
        person's name, which then folded a specialty into that person."""
        line = "- Dr. Samuel Adeyemi       Oncology Lead, Sub-Saharan Africa"
        span = "Samuel Adeyemi       Oncology"
        start = line.index(span)
        edit = normalize_span(
            line, Span(start, start + len(span), "PERSON", span, source="model")
        )
        assert edit is not None and edit.text == "Samuel Adeyemi"

    def test_wrapped_name_keeps_its_newline(self):
        """A single newline is a wrapped name, not a column boundary."""
        text = "I met Rebecca\nLindstrom today."
        edit = normalize_span(
            text, Span(6, 23, "PERSON", "Rebecca\nLindstrom", source="model")
        )
        assert edit is not None and edit.text == "Rebecca\nLindstrom"

    def test_pattern_spans_are_never_trimmed(self):
        """A MAC address is five colons; trimming it would break redaction."""
        text = 'x "00:1B:44:11:3A:B7" y'
        span = Span(3, 20, "MAC_ADDRESS", text[3:20], source="pattern")
        assert normalize_span(text, span) is span

    def test_uncased_scripts_survive(self):
        """Demanding a capital deletes every name in Arabic, CJK or Hebrew."""
        text = "أحمد فؤاد met us."
        span = Span(0, 9, "PERSON", text[0:9], source="model")
        edit = normalize_span(text, span)
        assert edit is not None
        assert unicodedata.category(edit.text[0]) == "Lo"

    def test_acronym_and_code_spans_are_not_names(self):
        text = "cites ICH E6 in the protocol"
        assert normalize_span(text, Span(6, 12, "PERSON", "ICH E6", source="model")) is None

    def test_normalisation_is_idempotent(self):
        text = "- Dr. Samuel Adeyemi       Oncology Lead"
        span = Span(6, 35, "PERSON", text[6:35], source="model")
        once = normalize_span(text, span)
        twice = normalize_span(text, once)
        assert once.start == twice.start and once.end == twice.end


class TestFieldLabels:
    def test_speaker_label_is_not_a_form_field(self):
        """Reading "Sarah Jenkins:" as a form field deleted the PERSON span at
        every turn of the transcript -- the highest-value position there is."""
        text = (
            "Sarah Jenkins: Alright everyone, thanks for joining us on the call today.\n"
            "Owner: Dr. Adeyemi\n"
            "Date: February 8, 2024\n"
        )
        labels = {text[s:e] for s, e in DocumentContext.build(text).field_labels}
        assert "Owner" in labels and "Date" in labels
        assert "Sarah Jenkins" not in labels

    def test_identifier_field_value_is_detected_by_position(self):
        """Shape alone caught one document's reference number and missed two."""
        text = "Matter No:         2024-AML-0876\n"
        values = {text[s:e] for s, e in DocumentContext.build(text).id_field_values}
        assert "2024-AML-0876" in values

    def test_address_field_value_is_detected_in_any_language(self):
        text = "Adresse: 12 Rue Victor Hugo, Paris, 75001\n"
        values = {text[s:e] for s, e in DocumentContext.build(text).address_field_values}
        assert "12 Rue Victor Hugo, Paris, 75001" in values


class TestPrivacyOverrides:
    def test_eponymous_firm_is_redacted_even_with_org_off(self):
        """"{{PERSON_1}}, Esq. (Partner, Whitfield & Barnes)" prints the
        surname one token from its own placeholder."""
        spans = [
            Span(0, 18, "PERSON", "Karen M. Whitfield"),
            Span(30, 52, "ORG", "Whitfield & Barnes LLP"),
            Span(60, 70, "ORG", "Acme Trading"),
        ]
        labels = {s.text: s.label for s in _mark_eponymous(spans)}
        assert labels["Whitfield & Barnes LLP"] == "EPONYMOUS_ORG"
        assert labels["Acme Trading"] == "ORG"

    def test_single_token_person_does_not_trigger_eponymy(self):
        spans = [Span(0, 5, "PERSON", "Brown"), Span(10, 22, "ORG", "Brown Paper Co")]
        assert {s.label for s in _mark_eponymous(spans)} == {"PERSON", "ORG"}

    def test_norp_is_redacted_under_every_profile(self):
        """Nationality, ethnicity and religion are special-category data, so
        they must not ride along with the ORG/LOCATION default change."""
        from pii.policy import PROFILES, resolve_types

        for profile in PROFILES:
            assert "NORP" in resolve_types(profile)

    def test_canonical_form_prefers_a_well_formed_name(self):
        """Longest-wins is what turned a loose span into data loss."""
        assert (
            max(["Samuel Adeyemi", "Samuel Adeyemi       Oncology"], key=_canonical_rank)
            == "Samuel Adeyemi"
        )


class TestTypeSanity:
    @pytest.mark.parametrize("date", ["2024-02-22", "08/29/2024", "22/02/2024"])
    def test_calendar_dates_are_not_phone_numbers(self, date):
        labels = {s.label for s in detect_patterns(f"Due: {date} please")}
        assert "PHONE" not in labels

    def test_dates_are_not_redacted_by_default(self):
        from pii.policy import resolve_types

        assert "DATE" not in resolve_types("balanced")

    def test_bic_accepts_non_european_countries(self):
        """CITIUS33 is CITI + US + 33; the EU VAT country list missed it and
        the code that identifies the bank printed beside the masked bank."""
        assert "SWIFT_BIC" in {s.label for s in detect_patterns("SWIFT code CITIUS33.")}


class TestAllCapsNames:
    """The acronym rule was deleting short all-caps names.

    It was added to reject "ICH E6" and instead dropped every name whose
    tokens are all short -- roughly 110 plaintext occurrences across four
    transcripts, two of which were still stamped "clean".
    """

    @pytest.mark.parametrize(
        ("name", "titled"),
        [
            ("KWAME MENSAH", "Kwame Mensah"),
            ("JOHN SMITH", "John Smith"),
            ("ROBERT CHEN JR.", "Robert Chen Jr."),
            ("AMARA NWOSU", "Amara Nwosu"),
            ("ROHAN MEHTA", "Rohan Mehta"),
        ],
    )
    def test_short_all_caps_names_survive(self, name, titled):
        """The document's own title-case form is what proves it is a name.

        Every one of these appears title-cased in its transcript header and
        shouted in the speaker labels, which is the situation the rule has to
        get right.
        """
        from pii.spanfix import _is_name_like

        document = f"Interviewee: {titled}\n[10:00:35] {name}:\nhello\n"
        context = DocumentContext.build(document)
        start = document.index(name)
        assert _is_name_like(name, start, start + len(name), context)

    def test_all_caps_line_stands_the_rule_down(self):
        """In an all-caps line casing is not evidence of anything."""
        from pii.spanfix import _is_name_like

        document = "[10:00:35] KWAME MENSAH:\n"
        context = DocumentContext.build(document)
        start = document.index("KWAME MENSAH")
        assert _is_name_like("KWAME MENSAH", start, start + 12, context)

    @pytest.mark.parametrize("code", ["ICH E6", "SOC 2", "AES-256", "BX-4471"])
    def test_codes_are_still_rejected(self, code):
        from pii.spanfix import _is_name_like

        assert not _is_name_like(code, 0, len(code), None)

    @pytest.mark.parametrize("acronym", ["SME", "CASB", "CFO"])
    def test_single_token_acronyms_are_still_rejected(self, acronym):
        assert _is_acronym_or_code(acronym)


class TestApostropheNames:
    """Quote-balancing was cutting names at the apostrophe, leaving the
    surname tail in plaintext and gluing the placeholder mid-token."""

    @pytest.mark.parametrize(
        "name",
        [
            "YUKI TANAKA-O'BRIEN",
            "James O'Connor",
            "MARGARET O'SULLIVAN",
            "Mario D'Angelo",
            "Fatou N'Diaye",
        ],
    )
    def test_internal_apostrophe_is_part_of_the_name(self, name):
        sentence = "we met " + name + " today"
        start = sentence.index(name)
        edit = normalize_span(
            sentence, Span(start, start + len(name), "PERSON", name, source="model")
        )
        assert edit is not None and edit.text == name

    def test_possessive_clitic_is_still_stripped(self):
        text = "that Blue Harbor's agent was"
        edit = normalize_span(text, Span(5, 18, "ORG", "Blue Harbor's", source="model"))
        assert edit is not None and edit.text == "Blue Harbor"

    def test_a_real_unbalanced_quote_still_trims(self):
        text = 'said "Department of No here'
        edit = normalize_span(text, Span(5, 27, "ORG", text[5:27], source="model"))
        assert edit is None or '"' not in edit.text


class TestSpeakerFormats:
    TRANSCRIPT = (
        "[14:30:15] JAMES O'CONNOR:\nHello everyone.\n"
        "[14:31:02] AMARA NWOSU:\nGood morning.\n"
        "[14:32:00] JAMES O'CONNOR:\nLet us begin.\n"
        "[14:33:00] AMARA NWOSU:\nAgreed.\n"
    )

    def test_bracketed_timestamp_roster(self):
        """This format left the roster empty on all four documents."""
        from pii.roster import extract_roster

        assert set(extract_roster(self.TRANSCRIPT)) == {"JAMES O'CONNOR", "AMARA NWOSU"}

    def test_unredacted_speaker_label_is_a_high_finding(self):
        """The check that would have caught all four documents."""
        from pii.residual import scan_residual

        text = "[10:00:10] {{PERSON_1}}:\nhi\n[10:00:35] KWAME MENSAH:\nhello\n"
        findings = scan_residual(text)
        assert any(
            f.rule == "unredacted_speaker_label" and f.severity == "high" for f in findings
        )

    def test_fully_redacted_transcript_is_silent(self):
        from pii.residual import scan_residual

        text = "[10:00:10] {{PERSON_1}}:\nhi\n[10:00:35] {{PERSON_2}}:\nhello\n"
        assert not [f for f in scan_residual(text) if f.rule == "unredacted_speaker_label"]

    def test_header_fields_do_not_fire(self):
        """"Interviewer:" and "Note:" share a speaker label's shape."""
        from pii.residual import scan_residual

        text = "Interview Title: Quarterly Review\nNote: nothing to add\n"
        assert not [f for f in scan_residual(text) if f.rule == "unredacted_speaker_label"]


class TestSeverityCalibration:
    def test_case_variant_of_a_name_is_high(self):
        """Two documents were stamped clean because "Kwame" matching
        "KWAME MENSAH" was graded low, and low does not gate."""
        text = "Interviewee: {{PERSON_2}}\n[10:00:35] KWAME MENSAH:\n"
        leaks = audit(text, {"{{PERSON_2}}": {"Kwame"}}, [], DocumentContext.build(text))
        assert leaks and leaks[0]["severity"] == "high"

    def test_case_variant_of_an_ordinary_word_stays_low(self):
        """Redacting the name "Mark" must not make every "mark" a leak."""
        text = "please mark the box\n{{PERSON_1}} agreed. MARK agreed.\n"
        leaks = audit(text, {"{{PERSON_1}}": {"Mark"}}, [], DocumentContext.build(text))
        assert leaks and leaks[0]["severity"] == "low"

    @pytest.mark.parametrize("token", ["AES-256", "AES-128", "CVE-2024-21762"])
    def test_standards_are_not_identifiers(self, token):
        """These forced two documents to review and suppressed their output."""
        from pii.residual import scan_residual

        assert not [f for f in scan_residual("using " + token + " here") if not f.suppressed_by]


class TestNorpScope:
    @pytest.mark.parametrize(
        ("phrase", "norp", "redacted"),
        [
            # Released only on an explicit non-person noun.
            ("the European market grew", "European", False),
            ("system is Finacle, version 10.2.18", "Finacle", False),
            # Everything else stays masked, including constructions an
            # enumeration of person nouns would have missed.
            ("a Cypriot national named X", "Cypriot", True),
            ("British citizens here", "British", True),
            ("Yoruba-speaking populations", "Yoruba", True),
            ("She is Cypriot.", "Cypriot", True),
            ("Rohingya refugees arrived", "Rohingya", True),
            ("Nationality: Nigerian", "Nigerian", True),
            ("Sikh applicants were", "Sikh", True),
            ("He is Jewish.", "Jewish", True),
        ],
    )
    def test_norp_fails_closed(self, phrase, norp, redacted):
        """Article 9 data is released only on positive evidence.

        Listing person nouns instead meant any construction not thought of --
        "She is Cypriot", "Rohingya refugees" -- printed in plaintext.
        """
        context = DocumentContext.build(phrase)
        start = phrase.index(norp)
        assert context.releases_norp(start, start + len(norp)) is not redacted


class TestMissedIdentifiers:
    def test_swift_bic_with_a_copula(self):
        """"The SWIFT BIC is BHRTINBB" -- the label pattern could not match."""
        assert "SWIFT_BIC" in {s.label for s in detect_patterns("The SWIFT BIC is BHRTINBB.")}

    def test_slash_separated_case_reference(self):
        labels = {s.label for s in detect_patterns("reference was RBI/2023/CYB/0847.")}
        assert "CUSTOM_ID" in labels

    @pytest.mark.parametrize("token", ["ISO/IEC 27001", "TCP/IP", "and/or"])
    def test_slash_rule_ignores_technical_notation(self, token):
        assert "CUSTOM_ID" not in {s.label for s in detect_patterns("see " + token + " today")}


class TestLineWrappedNames:
    def test_a_name_split_by_a_newline_is_detectable(self):
        """is_plausible rejected any newline, so four names leaked entirely."""
        from pii.detector import is_plausible

        assert is_plausible("PERSON", "Priya\nDeshpande")
        assert not is_plausible("PERSON", "Priya\n\nDeshpande")
