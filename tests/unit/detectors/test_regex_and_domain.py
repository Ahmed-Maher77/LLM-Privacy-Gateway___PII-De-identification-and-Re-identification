"""Deterministic and domain-rule detection.

The false-positive cases are drawn from the real transcripts: a Teams
timestamp, a recording filename with an embedded datestamp, a currency range
and a version string all look phone-number-ish to a naive pattern.
"""

from __future__ import annotations

import pytest

from privacy_gateway.detectors.domain_detector import DomainDetector, DomainLexicon
from privacy_gateway.detectors.patterns import EMAIL_PATTERN, luhn_valid
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


# -- account identifiers -----------------------------------------------------

def test_detects_the_customer_id_from_the_sme_transcript():
    assert found("customer account BP-28491.", "CUSTOMER_ID") == ["BP-28491"]


@pytest.mark.parametrize("text", ["420 employees", "version 4.6", "BP28491", "bp-28491"])
def test_account_id_pattern_does_not_fire_on(text):
    assert found(text, "CUSTOMER_ID") == []


# -- url ---------------------------------------------------------------------

def test_detects_the_internal_api_url():
    text = "The API endpoint is `https://api.fleetcore.example.com/v2`"
    assert found(text, "URL") == ["https://api.fleetcore.example.com/v2"]


def test_url_does_not_swallow_a_sentence_ending_period():
    assert found("see https://example.com/docs. Next.", "URL") == ["https://example.com/docs"]


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

def test_luhn_accepts_a_valid_number():
    assert luhn_valid("4539578763621486")


def test_luhn_rejects_an_invalid_number():
    assert not luhn_valid("4539578763621487")


def test_credit_card_requires_a_valid_checksum():
    assert found("card 4539 5787 6362 1486", "CREDIT_CARD") == ["4539 5787 6362 1486"]
    assert found("card 4539 5787 6362 1487", "CREDIT_CARD") == []


# -- ip ----------------------------------------------------------------------

def test_detects_an_ipv4_address():
    assert found("host 192.168.10.24 down", "IP_ADDRESS") == ["192.168.10.24"]


def test_rejects_an_out_of_range_octet():
    assert found("build 999.1.1.1", "IP_ADDRESS") == []


# -- general -----------------------------------------------------------------

def test_every_detected_span_slices_back_to_its_own_text():
    text = "Mail a@b.com or call +44 7700 900123 about BP-28491 at https://x.example.com/p"
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
