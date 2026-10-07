"""Regression tests for the security defects found in the audited run.

Each test here corresponds to something that was actually broken, not to a
hypothetical. The names say which.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from pii import PIIMiddleware, detect_patterns, scan_residual
from pii.custom_patterns import PatternConfigError, _load_cached, build_rules, load_config
from pii.middleware import _reconcile_names, audit
from pii.policy import (
    DEFAULT_ALLOWLIST,
    allowlist_tokens,
    is_allowlisted,
    is_non_personal,
    is_technical_acronym,
)
from pii.reporting import summarize_findings, summarize_leaks
from pii.residual import digest, mask
from pii.structure import analyze_structure, protect_spans
from pii.titles import detect_titles
from pii.vault import PseudonymVault, find_template_literals, restore, restore_pattern

# The corpus lives in tests/fixtures/. These files used to be read from
# test_data/, which held byte-identical duplicates; resolving from the test
# file rather than the working directory also stops the suite depending on
# being invoked from the repository root.
FIXTURES = Path(__file__).resolve().parent / "fixtures"
TRANSCRIPT = FIXTURES / "transcript_test.txt"

# Every value that survived the audited run, plus the ones the brief listed.
LEAKED_VALUES = (
    "4532-0192-8834-5610",
    "482",
    "08/29",
    "122000049",
    "88301928475",
    "DL-8829401-X",
    "MEM-992014-A",
    "EMP-4029",
    "usr_991823",
    "00:1B:44:11:3A:B7",
    "742",
    "97477",
    "987-65-4321",
)

# Words that were wrongly masked as {{ORG_n}} and must stay readable.
PRESERVED_WORDS = (
    "CVV",
    "IP",
    "MAC",
    "JSON",
    "API",
    "Microsoft Teams",
    "HR Operations Specialist",
)


def _labels(text: str) -> set[str]:
    return {span.label for span in detect_patterns(text)}


class TestStructuredSecrets:
    @pytest.mark.parametrize(
        ("text", "label"),
        [
            ("the CVV is 482.", "CVV"),
            ("expires 08/29,", "CARD_EXPIRY"),
            ("routing number 122000049,", "ROUTING_NUMBER"),
            ("account number 88301928475.", "BANK_ACCOUNT"),
            ('"mac_address": "00:1B:44:11:3A:B7"', "MAC_ADDRESS"),
            ("licence is DL-8829401-X, issued", "CUSTOM_ID"),
            ("Member ID is MEM-992014-A, policy", "CUSTOM_ID"),
            ("742 Evergreen Terrace, Springfield, OR 97477", "ADDRESS"),
        ],
    )
    def test_each_missed_secret_is_now_found(self, text, label):
        assert label in _labels(text)

    def test_keyword_is_preserved_and_only_the_value_masked(self):
        """The failure in miniature: the word CVV was masked, the value was not."""
        span = next(s for s in detect_patterns("the CVV is 482.") if s.label == "CVV")
        assert span.text == "482"

    def test_address_is_one_span_not_three(self):
        spans = [s for s in detect_patterns("at 742 Evergreen Terrace, Springfield, OR 97477.")
                 if s.label == "ADDRESS"]
        assert len(spans) == 1
        assert spans[0].text == "742 Evergreen Terrace, Springfield, OR 97477"

    def test_routing_number_survives_a_failing_aba_checksum(self):
        assert "ROUTING_NUMBER" in _labels("routing number 122000049,")

    @pytest.mark.parametrize(
        "text",
        ["RFC-2616", "ISO-8601", "AES-256", "SHA-256", "COVID-19", "UTF-8",
         "Section-1234", "Chapter-1999", "Q3-2026"],
    )
    def test_technical_tokens_are_not_identifiers(self, text):
        assert "CUSTOM_ID" not in _labels(f"see {text} for details")

    def test_phone_does_not_truncate_a_decimal_mac(self):
        """PHONE used to claim the first five octets of a hyphenated MAC."""
        assert "PHONE" not in _labels("hw 00-11-22-33-44-55 here")

    def test_transcript_timecodes_are_still_not_phone_numbers(self):
        assert detect_patterns("Ahmed Farid   0:31\n30m 37s\n") == []


class TestResidualScanner:
    def test_flags_a_secret_that_was_never_detected(self):
        """The defect that produced 'clean: true' over six live secrets."""
        findings = scan_residual("The card number is 4532-0192-8834-5610 here.")
        assert any(f.rule == "card_shape" and f.severity == "high" for f in findings)

    def test_orphan_number_beside_a_placeholder(self):
        """'742' is only identifiable as a street number after redaction."""
        findings = scan_residual("address is 742 {{ORG_4}}, {{LOCATION_1}}")
        assert any(f.rule == "orphan_number_beside_placeholder" for f in findings)

    @pytest.mark.parametrize(
        "text",
        ["capped at $2,500.", "born in 1988.", "reconvene at 3:00 PM EST today.",
         "about 420 employees", "version 1.2.3.4 shipped"],
    )
    def test_benign_numbers_are_suppressed(self, text):
        assert [f for f in scan_residual(text) if f.severity == "high"] == []

    def test_clock_suppressor_does_not_eat_a_mac(self):
        findings = scan_residual('"mac": "00:1B:44:11:3A:B7"')
        assert any(f.rule == "mac" for f in findings)

    def test_expiry_is_low_in_prose_and_high_after_a_keyword(self):
        prose = scan_residual("the 08/29 figure")
        carded = scan_residual("expires 08/29,")
        assert not [f for f in prose if f.rule == "expiry" and f.severity == "high"]
        assert [f for f in carded if f.rule == "expiry" and f.severity == "high"]

    def test_placeholders_do_not_trigger_findings(self):
        assert scan_residual("{{PERSON_1}} met {{PERSON_12}}") == []

    def test_known_values_are_not_double_counted(self):
        text = "leftover 4532-0192-8834-5610"
        assert scan_residual(text, known_values=["4532-0192-8834-5610"]) == []


class TestFailClosed:
    def test_status_is_three_state_not_a_boolean(self):
        from pii.middleware import AnonymizationResult

        result = AnonymizationResult(sanitized="", mapping={})
        assert result.status == "clean"
        result.leaks = [{"value": "x", "severity": "high", "occurrences": 1}]
        assert result.status == "failed"
        assert not result.is_clean

    def test_audit_still_catches_a_detected_value_that_survived(self):
        leaks = audit("Lamia is here", {"{{PERSON_1}}": {"Lamia"}}, [])
        assert leaks[0]["severity"] == "high"


class TestPlaceholderInjection:
    def test_literal_in_input_is_found(self):
        spans = find_template_literals("attacker wrote {{PERSON_1}} here")
        assert [s.text for s in spans] == ["{{PERSON_1}}"]

    def test_sentinel_cannot_be_restored_into_a_name(self):
        """The exploit: a planted {{PERSON_1}} resolved to a real person."""
        vault = PseudonymVault()
        span = find_template_literals("{{PERSON_1}}")[0]
        sentinel = vault.escape_for(span)
        assert restore(sentinel, {"{{PERSON_1}}": "Sarah Jenkins"}) == sentinel
        assert "Sarah" not in sentinel

    def test_sentinel_survives_rebracketing_by_a_model(self):
        vault = PseudonymVault()
        sentinel = vault.escape_for(find_template_literals("{{PERSON_1}}")[0])
        echoed = "{{" + sentinel.strip("()") + "}}"
        assert "Sarah" not in restore(echoed, {"{{PERSON_1}}": "Sarah Jenkins"})

    def test_escapes_are_reversible_but_only_after_placeholders(self):
        vault = PseudonymVault()
        sentinel = vault.escape_for(find_template_literals("{{PERSON_1}}")[0])
        out = restore(sentinel, {"{{PERSON_1}}": "Sarah Jenkins"}, vault.escapes)
        assert out == "{{PERSON_1}}"

    def test_restore_ignores_tokens_this_run_never_minted(self):
        """<SECTION_1> in a model response is XML, not a placeholder."""
        assert restore("<SECTION_1>", {"{{PERSON_1}}": "X"}) == "<SECTION_1>"

    def test_restore_rejects_mismatched_brackets(self):
        assert restore("{PERSON_1]", {"{{PERSON_1}}": "X"}) == "{PERSON_1]"

    def test_empty_mapping_matches_nothing(self):
        assert restore_pattern({}).search("{{PERSON_1}}") is None


class TestStructurePreservation:
    BLOCK = '{\n  "user_id": "usr_991823",\n  "mac_address": "00:1B:44:11:3A:B7"\n}'

    def test_unfenced_json_is_detected(self):
        """The real transcript's block has no backticks anywhere."""
        structure = analyze_structure(f"JSON\n{self.BLOCK}\n")
        assert len(structure.regions) == 1
        assert structure.regions[0].kind == "json"

    def test_keys_are_identified(self):
        structure = analyze_structure(self.BLOCK)
        keys = {self.BLOCK[s:e] for s, e in structure.key_zones}
        assert keys == {'"user_id"', '"mac_address"'}

    def test_prose_spans_are_never_clipped(self):
        """A global comma rule would forbid matching a full address."""
        from pii.spans import Span

        text = "742 Evergreen Terrace, Springfield, OR 97477"
        structure = analyze_structure(text)
        span = Span(0, len(text), "ADDRESS", text, source="model")
        assert protect_spans(text, [span], structure) == [span]

    def test_key_zone_drops_an_org_span(self):
        from pii.spans import Span

        structure = analyze_structure(self.BLOCK)
        start = self.BLOCK.index('"user_id"')
        span = Span(start, start + 9, "ORG", '"user_id"', source="model")
        assert protect_spans(self.BLOCK, [span], structure) == []


class TestAllowlist:
    def test_multi_word_product_is_allowlisted(self):
        """The whole-span lookup could never match 'Microsoft Teams'."""
        tokens = allowlist_tokens(DEFAULT_ALLOWLIST)
        assert is_allowlisted("Microsoft Teams", tokens)

    @pytest.mark.parametrize("word", ["IP", "MAC", "CVV", "JSON", "API"])
    def test_acronyms_are_not_personal_data(self, word):
        """Asserts the decision, not list membership: these now qualify via
        the computed acronym rule rather than by being written down."""
        assert is_non_personal(word, allowlist_tokens(DEFAULT_ALLOWLIST))

    def test_a_participant_name_beats_the_allowlist(self):
        tokens = allowlist_tokens(DEFAULT_ALLOWLIST | {"java"})
        assert not is_allowlisted("Mark Java", tokens, protected={"java"})

    def test_allowlisting_mac_does_not_suppress_a_mac_address(self):
        assert "MAC_ADDRESS" in _labels('"mac": "00:1B:44:11:3A:B7"')


class TestTitles:
    def test_job_title_is_detected(self):
        titles = {s.text for s in detect_titles("David Miller (HR Operations Specialist)")}
        assert "HR Operations Specialist" in titles

    def test_honorific_is_not_a_job_title(self):
        """'Dr.' belongs to the person's name, not their job."""
        assert detect_titles("Dr. Eleanor Rostova at the hospital") == []

    def test_title_never_swallows_a_participant_name(self):
        """A title span is dropped unredacted, so a name inside one leaks.

        "Lala Maher head show" matched JOB_TITLE via the head noun "head",
        outranked the roster's "Maher" on length, and the surname then
        survived in plaintext.
        """
        middleware = PIIMiddleware(detectors=[], use_roster=False)
        titles = middleware._safe_titles(
            "Lala Maher head show", {"maher"}, []
        )
        assert titles == []

    def test_title_overlapping_a_detected_person_is_dropped(self):
        from pii.spans import Span

        text = "Eleanor Rostova manager of the team"
        person = Span(0, 15, "PERSON", "Eleanor Rostova", source="model")
        middleware = PIIMiddleware(detectors=[], use_roster=False)
        assert middleware._safe_titles(text, set(), [person]) == []

    def test_meeting_title_line_is_detected(self):
        spans = detect_titles("\U0001f399️ Transcript: Quarterly Engineering & Review\n")
        assert any(s.label == "MEETING_TITLE" for s in spans)


class TestCustomPatterns:
    def _write(self, tmp_path: Path, body: str) -> Path:
        path = tmp_path / "pii_patterns.toml"
        path.write_text(body, encoding="utf-8")
        _load_cached.cache_clear()
        return path

    def test_valid_config_adds_a_rule(self, tmp_path):
        path = self._write(tmp_path, """
version = 1
[[patterns]]
label = "BADGE_ID"
regex = '(?<![\\w-])BDG-\\d{5}(?![\\w-])'
examples = ["BDG-40291"]
counter_examples = ["BDG-40"]
""")
        rules = build_rules(load_config(path))
        assert any(rule.label == "BADGE_ID" for rule in rules)

    def test_example_that_does_not_match_is_rejected(self, tmp_path):
        """Turns a silent typo into a startup failure."""
        path = self._write(tmp_path, """
version = 1
[[patterns]]
label = "BADGE_ID"
regex = 'BDG-\\d{5}'
examples = ["NOPE-1"]
""")
        with pytest.raises(PatternConfigError, match="does not match"):
            load_config(path)

    def test_zero_width_regex_is_rejected(self, tmp_path):
        """It would emit end == start and blow up inside Span."""
        path = self._write(tmp_path, """
version = 1
[[patterns]]
label = "EMPTY"
regex = 'x*'
""")
        with pytest.raises(PatternConfigError, match="empty string"):
            load_config(path)

    def test_missing_file_is_not_an_error(self, tmp_path):
        assert load_config(tmp_path / "absent.toml").rules == ()


class TestReportRedaction:
    def test_short_values_mask_completely(self):
        """Revealing 2 of 3 CVV digits is not masking."""
        assert mask("482") == "***"

    def test_digest_is_salted(self):
        assert digest("987-65-4321", salt=b"a") != digest("987-65-4321", salt=b"b")

    def test_findings_never_serialize_the_value(self):
        findings = scan_residual("card 4532-0192-8834-5610 here")
        items = summarize_findings(findings, salt=b"s")
        assert items and all("value" not in item for item in items)
        assert all("4532" not in json.dumps(item) for item in items)

    def test_leaks_never_serialize_the_value(self):
        items = summarize_leaks([{"value": "987-65-4321", "severity": "high", "occurrences": 1}])
        assert "987-65-4321" not in json.dumps(items)


@pytest.fixture(scope="module")
def analysis():
    middleware = PIIMiddleware(on_leak="warn")
    return middleware.analyze(TRANSCRIPT.read_text(encoding="utf-8"))


@pytest.mark.slow
class TestAuditedTranscript:
    """The full pipeline against the document that produced the bad report."""

    @pytest.mark.parametrize("value", LEAKED_VALUES)
    def test_every_previously_leaked_value_is_gone(self, analysis, value):
        assert value not in analysis.sanitized

    @pytest.mark.parametrize("word", PRESERVED_WORDS)
    def test_over_redacted_words_are_preserved(self, analysis, word):
        assert word in analysis.sanitized

    def test_status_is_clean(self, analysis):
        assert analysis.status == "clean", analysis.residual

    def test_json_block_still_parses(self, analysis):
        block = re.search(r'\{\s*\n\s*"user_id".*?\n\}', analysis.sanitized, re.S)
        assert block is not None
        json.loads(block.group())

    def test_json_keys_survive_and_values_do_not(self, analysis):
        assert '"mac_address"' in analysis.sanitized
        assert '"mac_address": "{{MAC_ADDRESS_1}}"' in analysis.sanitized

    def test_doctor_stays_a_person(self, analysis):
        assert analysis.mapping.get("{{PERSON_5}}") == "Dr. Eleanor Rostova"
        assert "Eleanor" not in analysis.sanitized

    def test_address_restores_as_one_unit(self, analysis):
        values = set(analysis.mapping.values())
        assert "742 Evergreen Terrace, Springfield, OR 97477" in values


class TestCredentialsAndInternational:
    """Second audit round: a cURL payload and a European client."""

    CONNECTION = "postgresql://admin_user:P@ssw0rd2026!@10.0.4.15:5432/production_db"

    def test_connection_string_is_one_span(self):
        """It used to be shredded: EMAIL claimed 'ssw0rd2026!@10.0.4.15',
        leaving 'P@' and the username in cleartext."""
        spans = [s for s in detect_patterns(f'"db": "{self.CONNECTION}"')
                 if s.label == "CONNECTION_STRING"]
        assert len(spans) == 1
        assert spans[0].text == self.CONNECTION

    def test_email_no_longer_matches_inside_a_connection_string(self):
        """The final domain label must be alphabetic, so an IP host cannot
        pose as a domain."""
        assert "EMAIL" not in _labels(self.CONNECTION)

    @pytest.mark.parametrize(
        "address",
        ["user@example.com", "s.rodriguez85@protonmail.com",
         "sophia.rodriguez@aegis-health.eu", "a.b@sub.domain.co.uk"],
    )
    def test_real_emails_still_match(self, address):
        assert "EMAIL" in _labels(f"write to {address} today")

    def test_ip_literal_is_not_an_email(self):
        assert "EMAIL" not in _labels("root@192.168.1.1 logged in")

    @pytest.mark.parametrize(
        "phone",
        ["+49 30 1234567", "+44 20 7946 0912", "+1 (555) 019-2834",
         "+1-312-555-0143", "+33 1 42 68 53 00"],
    )
    def test_international_phone_formats(self, phone):
        """'+49 30 1234567' ends in a 7-digit block that the North American
        grouping could not express, so it leaked."""
        assert "PHONE" in _labels(f"call {phone} now")

    @pytest.mark.parametrize("vat", ["ES-B87654321", "ESB87654321", "DE123456789"])
    def test_eu_vat_is_detected(self, vat):
        assert "EU_VAT" in _labels(f"VAT number is {vat} for billing")

    def test_eu_vat_requires_a_digit(self):
        assert "EU_VAT" not in _labels("the DESIGNERS group")

    def test_swift_bic_keyword_form(self):
        spans = [s for s in detect_patterns("SWIFT/BIC code DBEKDEFFXXX here")
                 if s.label == "SWIFT_BIC"]
        assert spans and spans[0].text == "DBEKDEFFXXX"

    def test_bearer_token_masked_but_scheme_kept(self):
        text = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.usr_991823"'
        spans = [s for s in detect_patterns(text) if s.label == "CREDENTIAL"]
        assert spans
        assert all("Bearer" not in s.text for s in spans)

    def test_secret_assignment(self):
        assert "CREDENTIAL" in _labels('password = "hunter2hunter2"')

    def test_uk_address_includes_its_postcode(self):
        spans = [s for s in detect_patterns(
            "office at 10 Downing Street, Westminster, London SW1A 2AA, UK.")
            if s.label == "ADDRESS"]
        assert len(spans) == 1
        assert "SW1A 2AA" in spans[0].text

    def test_us_address_still_works(self):
        spans = [s for s in detect_patterns("at 742 Evergreen Terrace, Springfield, OR 97477.")
                 if s.label == "ADDRESS"]
        assert spans[0].text == "742 Evergreen Terrace, Springfield, OR 97477"

    @pytest.mark.parametrize("term", ["PCI", "DSS", "VAT", "SWIFT", "BIC"])
    def test_compliance_and_card_brands_are_not_personal_data(self, term):
        """These were being masked as {{ORG_n}}, mangling 'PCI-DSS'."""
        assert is_non_personal(term, allowlist_tokens(DEFAULT_ALLOWLIST))

    def test_allowlisting_swift_does_not_suppress_a_bic_code(self):
        assert "SWIFT_BIC" in _labels("SWIFT/BIC code DBEKDEFFXXX here")


@pytest.mark.slow
class TestCurlTranscript:
    """The second audited transcript, end to end."""

    @pytest.fixture(scope="class")
    def result(self):
        path = (FIXTURES / "transcript_test_2.txt")
        return PIIMiddleware(on_leak="warn").analyze(path.read_text(encoding="utf-8"))

    @pytest.mark.parametrize(
        "value",
        ["+49 30 1234567", "+44 20 7946 0912", "ES-B87654321", "DBEKDEFFXXX",
         "PAG98230149", "5412-7512-3412-8890", "891", "PHI-88209-X12",
         "eyJhbGciOiJIUzI1NiIs", "ssw0rd2026", "admin_user", "10.0.4.15",
         "172.16.254.1", "3A:80:41:FC:02:9A", "456-78-9012", "SW1A 2AA"],
    )
    def test_nothing_sensitive_survives(self, result, value):
        assert value not in result.sanitized

    @pytest.mark.parametrize(
        "term", ["PCI-DSS", "SWIFT/BIC", "VAT", "Master Card", "Microsoft Teams"]
    )
    def test_compliance_terms_survive(self, result, term):
        assert term in result.sanitized

    def test_bash_flags_and_json_quotes_intact(self, result):
        assert "-X POST" in result.sanitized
        assert '-H "Content-Type: application/json"' in result.sanitized
        assert '"db_connection": "{{CONNECTION_STRING_1}}"' in result.sanitized

    def test_status_is_clean(self, result):
        assert result.status == "clean", result.residual


class TestNameIdentityReconciliation:
    """Third audit round: a two-person interview came out as four people."""

    def test_bare_first_name_folds_into_the_full_name(self):
        """"Sarah Jenkins:" appears once, "Sarah:" eleven times, so only the
        short form cleared the speaker threshold and got its own identity."""
        assert _reconcile_names(["Sarah", "Marcus", "Sarah Jenkins", "Marcus Thorne"]) == [
            "Sarah Jenkins",
            "Marcus Thorne",
        ]

    def test_ambiguous_first_name_is_kept(self):
        """Three colleagues share "Ahmed", so it must not fold into any one."""
        names = ["Ahmed", "Ahmed Farid", "Ahmed Maher"]
        assert "Ahmed" in _reconcile_names(names)

    def test_lone_first_name_with_no_full_name_is_kept(self):
        assert _reconcile_names(["Sarah"]) == ["Sarah"]

    def test_surname_also_folds(self):
        assert _reconcile_names(["Jenkins", "Sarah Jenkins"]) == ["Sarah Jenkins"]


class TestTechnicalVocabulary:
    @pytest.mark.parametrize("term", ["SME", "CASB", "SIEM", "DLP", "MFA", "SOC2"])
    def test_short_all_caps_tokens_are_acronyms(self, term):
        """A requirements interview is dense with these and every one was
        being masked as an organisation."""
        assert is_technical_acronym(term)

    @pytest.mark.parametrize("term", ["BlueCross", "Okta", "Microsoft", "Inc", "Aegis"])
    def test_mixed_case_names_are_not_acronyms(self, term):
        assert not is_technical_acronym(term)

    @pytest.mark.parametrize("term", ["Okta", "OneDrive", "Splunk", "Inline"])
    def test_products_are_not_personal_data(self, term):
        assert is_non_personal(term, allowlist_tokens(DEFAULT_ALLOWLIST))

    @pytest.mark.parametrize("term", ["Security Team", "Shadow IT", "Master Card"])
    def test_generic_phrases_survive_via_the_profile(self, term):
        """No longer allowlisted by name. They are ORG, and ORG is not
        redacted by default -- which is why the list could shrink."""
        from pii.policy import resolve_types

        assert "ORG" not in resolve_types("balanced")

    @pytest.mark.parametrize("role", ["CFO", "CISO", "VP"])
    def test_role_acronyms_are_job_titles_not_people(self, role):
        spans = detect_titles(f"if the {role} uploads a report")
        assert any(s.label == "JOB_TITLE" and s.text == role for s in spans)


class TestSpanHygiene:
    def test_quotes_split_a_span(self):
        """'the "Department of No' swallowed an article and an opening quote,
        leaving a dangling '."' behind."""
        from pii.detector import build_spans

        text = 'not the "Department of No."'
        spans = build_spans(text, 4, len(text) - 1, "ORG", 0.9)
        assert all('"' not in span.text for span in spans)

    def test_leading_article_is_stripped(self):
        from pii.detector import build_spans

        spans = build_spans("the Acme Corporation", 0, 20, "ORG", 0.9)
        assert spans and not spans[0].text.lower().startswith("the ")


@pytest.mark.slow
class TestInterviewTranscript:
    """transcript_test_3: two people, and a great deal of jargon."""

    @pytest.fixture(scope="class")
    def result(self):
        path = (FIXTURES / "transcript_test_3.txt")
        return PIIMiddleware(on_leak="warn").analyze(path.read_text(encoding="utf-8"))

    def test_only_the_two_real_people_are_redacted(self, result):
        assert set(result.mapping.values()) == {"Sarah Jenkins", "Marcus Thorne"}

    def test_each_person_has_exactly_one_placeholder(self, result):
        """The defect: Sarah Jenkins/Sarah and Marcus Thorne/Marcus were four."""
        assert len(result.mapping) == 2

    @pytest.mark.parametrize(
        "term",
        ["SME", "CASB", "SIEM", "DLP", "MFA", "GDPR", "SOC2", "Okta", "OneDrive",
         "Splunk", "GitHub", "Jira", "Slack", "Dropbox", "AWS", "Shadow IT",
         "Inline", "CFO", "Security Team", "Multi-Factor Authentication"],
    )
    def test_technical_vocabulary_survives(self, result, term):
        assert term in result.sanitized

    def test_no_name_survives(self, result):
        for name in ("Sarah", "Jenkins", "Marcus", "Thorne"):
            assert name not in result.sanitized

    def test_punctuation_is_not_damaged(self, result):
        source = (FIXTURES / "transcript_test_3.txt").read_text(encoding="utf-8")
        assert result.sanitized.count('"') == source.count('"')
        assert result.sanitized.count("(") == source.count("(")
        assert 'not the "Department of No."' in result.sanitized
