"""Tests for date detection/pseudonymization and entity exclusions.

Verifies that:
1. Dates (calendar dates, DOB, expiration dates) are detected and pseudonymized reversibly.
2. Excluded categories (organization, location/address, passport, account number,
   IP address, URL, session token, geo, device ID) are NOT detected or masked.
"""

from __future__ import annotations

import pytest

from privacy_gateway.config import DetectorSettings, Settings
from privacy_gateway.entities.entity import make_entity
from privacy_gateway.gateway import GatewayRequest, PrivacyGateway
from privacy_gateway.llm.mock_client import EchoLLMClient
from privacy_gateway.policy.actions import Action
from privacy_gateway.policy.engine import PolicyEngine


@pytest.fixture
def gateway():
    settings = Settings(
        detectors=DetectorSettings(
            enabled=("regex", "registry", "domain"),
            required=("regex", "registry"),
        )
    )
    return PrivacyGateway(settings, llm=EchoLLMClient())


def test_date_is_detected_and_pseudonymized(gateway):
    text = "Jean-Luc was born on 29 Feb 1964 and the incident was dated April 3, 2025."
    result = gateway.run(GatewayRequest(text=text, conversation_id="c-date-test"))
    
    assert "29 Feb 1964" not in result.sanitized_input
    assert "April 3, 2025" not in result.sanitized_input
    assert "<DATE_001>" in result.sanitized_input
    assert "<DATE_002>" in result.sanitized_input
    
    # Verify restorable in mapping store
    dates = {e.canonical for e in result.store.entries() if e.entity_type == "DATE"}
    assert "29 Feb 1964" in dates
    assert "April 3, 2025" in dates


def test_date_is_reidentified_properly(gateway):
    text = "The event happened on September 22, 2026."
    result = gateway.run(GatewayRequest(text=text, conversation_id="c-reid-date"))
    assert "<DATE_001>" in result.sanitized_input
    assert "September 22, 2026" in result.output


def test_card_expiration_date_is_detected_as_date(gateway):
    text = "Card details: Visa 4539 1488 0343 6467, exp 09/27, CVV 331."
    result = gateway.run(GatewayRequest(text=text, conversation_id="c-exp-date"))
    assert "09/27" not in result.sanitized_input
    assert any(e.canonical == "09/27" and e.entity_type == "DATE" for e in result.store.entries())


def test_meeting_timestamps_are_not_detected_as_dates(gateway):
    text = "Speaker: Ahmed Hassan\n[00:04:12] Meeting started at 10:30."
    result = gateway.run(GatewayRequest(text=text, conversation_id="c-time-date"))
    assert "00:04:12" in result.sanitized_input
    assert "10:30" in result.sanitized_input
    assert not any(e.canonical in ("00:04:12", "10:30") for e in result.store.entries())


@pytest.mark.parametrize(
    ("excluded_snippet", "category"),
    [
        ("Bluepeak Financial Services", "organization"),
        ("TechHarbor Electronics", "organization"),
        ("1600 Amphitheatre Parkway, Mountain View, CA 94043", "address"),
        ("Marseille", "location"),
        ("Passport #19AB45678", "passport"),
        ("Account number: 9876543210", "account_number"),
        ("IBAN: FR76 3000 6000 0112 3456 7890 189", "account_number"),
        ("192.168.14.22", "ip_address"),
        ("203.0.113.45", "ip_address"),
        ("https://api.internal-service.net/v1/auth", "url"),
        ("session_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy.payload", "session_token"),
        ("geo: 48.8566° N, 2.3522° E", "geo"),
        ("device_id: iPhone14,5 / iOS 17.2", "device_id"),
        ("mac_address: 00:1B:44:11:3A:B7", "device_id"),
    ],
)
def test_excluded_entities_are_preserved_in_plain_text(gateway, excluded_snippet, category):
    text = f"Context note: verifying {excluded_snippet} with customer."
    result = gateway.run(GatewayRequest(text=text, conversation_id=f"c-ex-{category}"))
    assert excluded_snippet in result.sanitized_input
    assert not any(e.canonical == excluded_snippet for e in result.store.entries())


def test_policy_rules_for_excluded_types_are_allow():
    policy = PolicyEngine()
    for etype in [
        "ORGANIZATION",
        "LOCATION",
        "ADDRESS",
        "ACCOUNT_IDENTIFIER",
        "CUSTOMER_ID",
        "IP_ADDRESS",
        "URL",
        "INTERNAL_URL",
        "PASSPORT",
        "PASSPORT_NUMBER",
        "SESSION_TOKEN",
        "GEO",
        "DEVICE_ID",
    ]:
        dummy = make_entity(
            text_source="dummy text",
            start=0,
            end=5,
            entity_type=etype,
            confidence=0.99,
            detector="test",
            priority=50,
        )
        assert policy.decide(dummy).action is Action.ALLOW, f"{etype} must be Action.ALLOW"


def test_aggregator_rejects_invalid_date_durations_and_bare_numbers():
    from privacy_gateway.aggregation.aggregator import EntityAggregator
    from privacy_gateway.entities.spans import SpanVerdict

    aggregator = EntityAggregator()
    text = "Duration: 26 seconds and 1 minute 22 at 02:50 with bare 46 and 52."

    candidates = [
        make_entity(text_source=text, start=text.index("26 seconds"), end=text.index("26 seconds") + 10, entity_type="DATE", confidence=0.85, detector="presidio"),
        make_entity(text_source=text, start=text.index("1 minute 22"), end=text.index("1 minute 22") + 11, entity_type="DATE", confidence=0.85, detector="presidio"),
        make_entity(text_source=text, start=text.index("02:50"), end=text.index("02:50") + 5, entity_type="DATE", confidence=0.85, detector="presidio"),
        make_entity(text_source=text, start=text.index("46"), end=text.index("46") + 2, entity_type="DATE", confidence=0.85, detector="presidio"),
        make_entity(text_source=text, start=text.index("52"), end=text.index("52") + 2, entity_type="DATE", confidence=0.85, detector="presidio"),
    ]
    res = aggregator.aggregate(candidates, text)
    assert len(res.entities) == 0
    assert all(r.verdict == SpanVerdict.INVALID_DATE for r in res.rejected)
