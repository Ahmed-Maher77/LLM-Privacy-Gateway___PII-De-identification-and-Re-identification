"""Deterministic and domain-rule detection.

The false-positive cases are drawn from the real transcripts: a Teams
timestamp, a recording filename with an embedded datestamp, a currency range
and a version string all look phone-number-ish to a naive pattern.
"""

from __future__ import annotations

import pytest

from privacy_gateway.detectors.domain_detector import DomainDetector, DomainLexicon
from privacy_gateway.detectors.patterns import EMAIL_PATTERN
from privacy_gateway.detectors.regex_detector import RegexDetector
from privacy_gateway.errors import ConfigError

R = RegexDetector()


def found(text, entity_type=None):
    out = R.detect(text)
    if entity_type:
        out = [e for e in out if e.entity_type == entity_type]
    return [e.text for e in out]


# -- email -------------------------------------------------------------------

def test_detects_a_plain_email():
    assert found("mail sarah.mitchell@example.com now", "EMAIL") == [
        "sarah.mitchell@example.com"
    ]


def test_email_pattern_is_preserved_verbatim_including_its_backtick_quirk():
    # EMAIL_PATTERN is carried over byte-identically from the prototype. Its
    # local-part class contains a backtick, so a markdown-code-spanned address
    # matches one character early. This is pinned deliberately: the fix lives
    # in the aggregation trim step, which repairs every detector's wrappers
    # rather than special-casing this one pattern.
    text = "`michael.brown@example.com`"
    m = EMAIL_PATTERN.search(text)
    assert m.group().startswith("`")


def test_the_trim_step_repairs_the_backticked_span():
    from privacy_gateway.entities.spans import realign

    text = "`michael.brown@example.com`"
    entity = R.detect(text)[0]
    assert realign(entity, text, expand=False).text == "michael.brown@example.com"


# -- account identifiers excluded from detection -----------------------------

def test_account_and_customer_identifiers_are_excluded_from_detection():
    assert found("customer account BP-28491.", "CUSTOMER_ID") == []
    assert found('"account_id": "CUST-2026-0042"', "CUSTOMER_ID") == []
    assert found("mac_address: 00:1B:44:11:3A:B7", "ACCOUNT_IDENTIFIER") == []
    assert found("00-1B-44-11-3A-B7", "ACCOUNT_IDENTIFIER") == []
    assert found("SWIFT: NWBKGB2L", "ACCOUNT_IDENTIFIER") == []
    assert found("SWIFT/BIC code DBEKDEFF002", "ACCOUNT_IDENTIFIER") == []
    assert found("Routing number: 122000049", "ACCOUNT_IDENTIFIER") == []
    assert found("Account number: 9876543210", "ACCOUNT_IDENTIFIER") == []


def test_detects_a_social_security_number():
    assert found("SSN: 123-45-6789", "SSN") == ["123-45-6789"]


# -- url excluded from detection ---------------------------------------------

def test_urls_are_excluded_from_detection():
    text = "The API endpoint is `https://api.fleetcore.example.com/v2`"
    assert found(text, "URL") == []
    assert found("see https://example.com/docs. Next.", "URL") == []


# -- date detection ----------------------------------------------------------

def test_detects_day_month_year_date():
    assert found("born on 29 Feb 1964 (yes, leap year)", "DATE") == ["29 Feb 1964"]
    assert found("meeting on 22 Sep 2026", "DATE") == ["22 Sep 2026"]
    assert found("deadline by 09 Oct 2026", "DATE") == ["09 Oct 2026"]


def test_detects_month_day_year_date():
    assert found("Date: April 3, 2025", "DATE") == ["April 3, 2025"]
    assert found("charge dated April 1st", "DATE") == ["April 1st"]
    assert found("September 24, 2026", "DATE") == ["September 24, 2026"]


def test_detects_iso_and_numeric_dates():
    assert found("DOB 1985-04-12 confirmed", "DATE") == ["1985-04-12"]
    assert found("signed 29/02/1964", "DATE") == ["29/02/1964"]


def test_detects_expiration_date():
    assert found("exp 09/27, CVV 331", "DATE") == ["09/27"]


# -- phone -------------------------------------------------------------------

def test_detects_an_international_number():
    assert found("call `+44 7700 900123`", "PHONE") == ["+44 7700 900123"]


def test_detects_a_grouped_national_number():
    assert found("call 020 7946 0958", "PHONE") == ["020 7946 0958"]


@pytest.mark.parametrize(
    "text",
    [
        "Ahmed Farid   0:31 ",
        "Meeting-20260101_090000UTC-Meeting Recording",
        "September 24, 2026, 10:30AM",
        "30m 37s",
        "$180,000-$250,000",
        "around 420 employees",
        "version 4.6",
        "at least 70% of our support employees",
    ],
)
def test_phone_pattern_does_not_fire_on_real_transcript_text(text):
    assert found(text, "PHONE") == []


# -- credit card -------------------------------------------------------------

def test_credit_card_shaped_numbers_are_detected_regardless_of_luhn():
    # Luhn validity no longer gates detection: a card-shaped number containing
    # a transcription typo, or the kind of plausible-but-invalid test number
    # this project's own test corpus turned out to use, must still be caught.
    assert found("card 4539 5787 6362 1486", "CREDIT_CARD") == ["4539 5787 6362 1486"]
    assert found("card 4539 5787 6362 1487", "CREDIT_CARD") == ["4539 5787 6362 1487"]


# -- ip excluded from detection ----------------------------------------------

def test_ip_addresses_are_excluded_from_detection():
    assert found("host 192.168.10.24 down", "IP_ADDRESS") == []
    assert found("build 999.1.1.1", "IP_ADDRESS") == []


# -- general -----------------------------------------------------------------

def test_every_detected_span_slices_back_to_its_own_text():
    text = "Mail a@b.com or call +44 7700 900123 born 29 Feb 1964 with SSN 123-45-6789"
    for e in R.detect(text):
        assert text[e.start : e.end] == e.text


def test_empty_text_yields_nothing():
    assert R.detect("") == ()


def test_detector_reports_its_name_and_priority():
    e = R.detect("mail a@b.com")[0]
    assert e.detector == "regex"
    assert e.priority == 90


# -- domain lexicon ----------------------------------------------------------

LEXICON = DomainLexicon.from_dict(
    {
        "internal_systems": {"terms": ["FleetCore", "CustomerDesk"], "confidence": 0.95},
        "customers": {"terms": ["BrightPath Logistics"], "confidence": 0.92},
        "patterns": {
            "rules": [["EMPLOYEE", r"(?<![\w-])EMP-\d{3,10}(?![\w-])", 0.95, "employee_id"]]
        },
    }
)
D = DomainDetector(LEXICON)


def dfound(text, entity_type=None):
    out = D.detect(text)
    if entity_type:
        out = [e for e in out if e.entity_type == entity_type]
    return [e.text for e in out]


def test_lexicon_term_is_detected():
    assert dfound("We run FleetCore daily.", "INTERNAL_SYSTEM") == ["FleetCore"]


def test_lexicon_matching_is_case_insensitive():
    assert dfound("the fleetcore api", "INTERNAL_SYSTEM") == ["fleetcore"]


def test_lexicon_respects_word_boundaries():
    assert dfound("FleetCoreX is different") == []


def test_longest_lexicon_term_wins():
    assert dfound("for BrightPath Logistics today", "CUSTOMER") == ["BrightPath Logistics"]


def test_lexicon_tolerates_extra_whitespace_in_a_multiword_term():
    assert dfound("for BrightPath  Logistics today", "CUSTOMER") == ["BrightPath  Logistics"]


def test_configured_pattern_rule_is_applied():
    assert dfound("ticket for EMP-4417", "EMPLOYEE") == ["EMP-4417"]


def test_domain_spans_slice_back_to_their_text():
    text = "FleetCore and CustomerDesk serve BrightPath Logistics (EMP-4417)."
    for e in D.detect(text):
        assert text[e.start : e.end] == e.text


def test_an_empty_lexicon_detects_nothing():
    assert DomainDetector(DomainLexicon()).detect("FleetCore") == ()


def test_lexicon_rejects_an_invalid_confidence():
    with pytest.raises(ConfigError):
        DomainLexicon.from_dict({"customers": {"terms": ["X"], "confidence": 5}})


def test_lexicon_rejects_an_uncompilable_pattern():
    with pytest.raises(ConfigError):
        DomainLexicon.from_dict({"patterns": {"rules": [["PERSON", "([", 0.9, "bad"]]}})


def test_lexicon_rejects_a_malformed_rule_row():
    with pytest.raises(ConfigError):
        DomainLexicon.from_dict({"patterns": {"rules": [["PERSON", "x"]]}})


def test_shipped_lexicon_loads_and_covers_the_sme_systems(repo_root):
    lexicon = DomainLexicon.load(repo_root / "config" / "domain_lexicon.toml")
    detector = DomainDetector(lexicon)
    text = "FleetCore, CustomerDesk, BillingPro and OpsHub serve BrightPath Logistics."
    detected = {e.text for e in detector.detect(text)}
    assert {"FleetCore", "CustomerDesk", "BillingPro", "OpsHub", "BrightPath Logistics"} <= detected
