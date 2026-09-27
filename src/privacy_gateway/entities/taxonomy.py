"""The canonical sensitive-data taxonomy.

"PII" is only one category. The gateway protects business-confidential
categories (internal systems, customer identifiers, contracts) that a generic
NER model has no concept of, which is why detection is layered rather than
delegated to a single model.
"""

from __future__ import annotations

from enum import StrEnum


class EntityType(StrEnum):
    PERSON = "PERSON"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    ADDRESS = "ADDRESS"
    ORGANIZATION = "ORGANIZATION"
    CUSTOMER = "CUSTOMER"
    CUSTOMER_ID = "CUSTOMER_ID"
    STAKEHOLDER = "STAKEHOLDER"
    EMPLOYEE = "EMPLOYEE"
    PROJECT = "PROJECT"
    INTERNAL_SYSTEM = "INTERNAL_SYSTEM"
    INTERNAL_SERVICE = "INTERNAL_SERVICE"
    INTERNAL_URL = "INTERNAL_URL"
    CONTRACT = "CONTRACT"
    ACCOUNT_IDENTIFIER = "ACCOUNT_IDENTIFIER"
    CONFIDENTIAL_BUSINESS_INFORMATION = "CONFIDENTIAL_BUSINESS_INFORMATION"
    LOCATION = "LOCATION"
    DATE = "DATE"
    IP_ADDRESS = "IP_ADDRESS"
    CREDIT_CARD = "CREDIT_CARD"
    URL = "URL"
    #: A placeholder-shaped token found in the *input*. Neutralised before
    #: detection so an attacker cannot seed a placeholder and have the gateway
    #: restore somebody else's value into it.
    LITERAL = "LITERAL"


#: Types whose spans must never cross a line break. A PERSON name spanning a
#: newline is always a detector error in a transcript.
LINE_BOUNDED: frozenset[str] = frozenset(
    {
        EntityType.PERSON,
        EntityType.ORGANIZATION,
        EntityType.LOCATION,
        EntityType.CUSTOMER,
        EntityType.EMPLOYEE,
        EntityType.STAKEHOLDER,
        EntityType.INTERNAL_SYSTEM,
        EntityType.INTERNAL_SERVICE,
        EntityType.PROJECT,
    }
)

#: Types that name a human being. They share one placeholder counter so that a
#: reader is not asked to track three parallel numbering schemes for people.
PERSON_LIKE: frozenset[str] = frozenset(
    {EntityType.PERSON, EntityType.EMPLOYEE, EntityType.STAKEHOLDER}
)

#: Normalisation of third-party detector labels onto the canonical taxonomy.
#: ``None`` means "drop": MISC carries no privacy meaning and NRP (nationality /
#: religion / political affiliation) is out of scope for v1.
DETECTOR_TYPE_MAP: dict[str, str | None] = {
    "PER": EntityType.PERSON,
    "PERSON": EntityType.PERSON,
    "ORG": EntityType.ORGANIZATION,
    "ORGANIZATION": EntityType.ORGANIZATION,
    "LOC": EntityType.LOCATION,
    "GPE": EntityType.LOCATION,
    "LOCATION": EntityType.LOCATION,
    "EMAIL_ADDRESS": EntityType.EMAIL,
    "PHONE_NUMBER": EntityType.PHONE,
    "CREDIT_CARD": EntityType.CREDIT_CARD,
    "IP_ADDRESS": EntityType.IP_ADDRESS,
    "URL": EntityType.URL,
    "DATE_TIME": EntityType.DATE,
    "MISC": None,
    "NRP": None,
}


def canonical_type(raw: str) -> str | None:
    """Map a detector-specific label onto the taxonomy, or ``None`` to drop it."""
    key = raw.strip().upper()
    if key in DETECTOR_TYPE_MAP:
        return DETECTOR_TYPE_MAP[key]
    return key if key in set(EntityType) else key or None
