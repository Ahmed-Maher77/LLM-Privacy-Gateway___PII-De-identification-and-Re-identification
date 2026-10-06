"""Policy actions and per-type rules.

Detection and protection are different questions. A detector reports what it
saw; the policy layer decides what this deployment considers sensitive. Keeping
that decision out of the detectors is what makes the taxonomy tunable without a
release, and what lets the same detection stack serve a strict and a permissive
deployment.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..entities.taxonomy import EntityType


class Action(StrEnum):
    #: Replace with a reversible placeholder. The value enters the mapping.
    PSEUDONYMIZE = "pseudonymize"
    #: Replace with a fixed marker. Irreversible, never enters the mapping.
    REDACT = "redact"
    #: Replace with a partially masked form. Irreversible.
    MASK = "mask"
    #: Leave untouched.
    ALLOW = "allow"


#: Actions that rewrite the text.
TRANSFORMING = frozenset({Action.PSEUDONYMIZE, Action.REDACT, Action.MASK})
#: Actions whose original value is recoverable afterwards.
REVERSIBLE = frozenset({Action.PSEUDONYMIZE})


@dataclass(frozen=True, slots=True)
class EntityRule:
    entity_type: str
    action: Action = Action.PSEUDONYMIZE
    min_confidence: float = 0.60
    placeholder_prefix: str = "ENTITY"
    case_sensitive: bool = False
    max_chars: int = 96

    def __post_init__(self) -> None:
        if not 0.0 <= self.min_confidence <= 1.0:
            raise ValueError(f"{self.entity_type}: min_confidence must lie in [0.0, 1.0]")
        if not self.placeholder_prefix.isupper() or not self.placeholder_prefix.isalnum():
            raise ValueError(
                f"{self.entity_type}: placeholder_prefix must be upper-case alphanumeric"
            )

    @property
    def restorable(self) -> bool:
        return self.action in REVERSIBLE


def _rule(entity_type, action, min_confidence, prefix, case_sensitive=False, max_chars=96):
    return EntityRule(
        entity_type=str(entity_type),
        action=action,
        min_confidence=min_confidence,
        placeholder_prefix=prefix,
        case_sensitive=case_sensitive,
        max_chars=max_chars,
    )


#: Shipped defaults.
#:
#: PERSON, EMPLOYEE and STAKEHOLDER deliberately share the ``PERSON`` prefix, so
#: a reader tracks one numbering scheme for people rather than three.
#:
#: DATE is PSEUDONYMIZE. Calendar dates, birth dates, and expiration dates are
#: pseudonymized with the <DATE_xxx> prefix. Bare clock timestamps (e.g. 00:04:12)
#: and durations are filtered at aggregation to preserve transcript structure.
#: Deployments can adjust this in config/policy.toml.
DEFAULT_RULES: dict[str, EntityRule] = {
    str(r.entity_type): r
    for r in (
        _rule(EntityType.PERSON, Action.PSEUDONYMIZE, 0.55, "PERSON", max_chars=64),
        _rule(EntityType.EMPLOYEE, Action.PSEUDONYMIZE, 0.60, "PERSON", max_chars=64),
        _rule(EntityType.STAKEHOLDER, Action.PSEUDONYMIZE, 0.60, "PERSON", max_chars=64),
        _rule(EntityType.EMAIL, Action.PSEUDONYMIZE, 0.90, "EMAIL", case_sensitive=True),
        _rule(EntityType.PHONE, Action.PSEUDONYMIZE, 0.70, "PHONE", case_sensitive=True),
        _rule(EntityType.ADDRESS, Action.ALLOW, 0.0, "ADDRESS", max_chars=120),
        _rule(EntityType.ORGANIZATION, Action.ALLOW, 0.0, "ORG"),
        _rule(EntityType.CUSTOMER, Action.PSEUDONYMIZE, 0.60, "CUSTOMER"),
        _rule(EntityType.CUSTOMER_ID, Action.ALLOW, 0.0, "CUSTID", case_sensitive=True),
        _rule(EntityType.PROJECT, Action.PSEUDONYMIZE, 0.70, "PROJECT"),
        _rule(EntityType.INTERNAL_SYSTEM, Action.PSEUDONYMIZE, 0.70, "SYSTEM"),
        _rule(EntityType.INTERNAL_SERVICE, Action.PSEUDONYMIZE, 0.70, "SERVICE"),
        _rule(EntityType.INTERNAL_URL, Action.ALLOW, 0.0, "URL", case_sensitive=True),
        _rule(EntityType.URL, Action.ALLOW, 0.0, "URL", case_sensitive=True, max_chars=300),
        _rule(EntityType.CONTRACT, Action.PSEUDONYMIZE, 0.70, "CONTRACT", case_sensitive=True),
        _rule(
            EntityType.ACCOUNT_IDENTIFIER, Action.ALLOW, 0.0, "ACCOUNT", case_sensitive=True
        ),
        _rule(
            EntityType.CONFIDENTIAL_BUSINESS_INFORMATION,
            Action.PSEUDONYMIZE,
            0.70,
            "CONFIDENTIAL",
            # Case-sensitive: this bucket now also covers secrets (API keys,
            # connection-string credentials), whose casing is part of the
            # literal value, not a stylistic variation to fold away.
            case_sensitive=True,
            max_chars=200,
        ),
        _rule(EntityType.CREDIT_CARD, Action.PSEUDONYMIZE, 0.90, "CARD", case_sensitive=True),
        _rule(EntityType.IP_ADDRESS, Action.ALLOW, 0.0, "IP", case_sensitive=True),
        _rule(EntityType.LOCATION, Action.ALLOW, 0.0, "LOCATION"),
        _rule(EntityType.DATE, Action.PSEUDONYMIZE, 0.70, "DATE"),
        _rule(EntityType.SSN, Action.PSEUDONYMIZE, 0.85, "SSN", case_sensitive=True),
        # Explicit ALLOW rules for other excluded categories:
        _rule("PASSPORT", Action.ALLOW, 0.0, "PASSPORT"),
        _rule("PASSPORT_NUMBER", Action.ALLOW, 0.0, "PASSPORT"),
        _rule("SESSION_TOKEN", Action.ALLOW, 0.0, "TOKEN"),
        _rule("GEO", Action.ALLOW, 0.0, "GEO"),
        _rule("DEVICE_ID", Action.ALLOW, 0.0, "DEVICE"),
        # A placeholder-shaped token found in the input. Pseudonymizing it is
        # what neutralises the injection: it becomes an ordinary mapped value
        # and restores to exactly the literal the user typed.
        _rule(EntityType.LITERAL, Action.PSEUDONYMIZE, 0.0, "LITERAL", case_sensitive=True),
    )
}

#: Used when a detector reports a type nobody has configured. Defaults to
#: protecting it: a new detector emitting an unknown label must not silently
#: leak.
FALLBACK_RULE = EntityRule(
    entity_type="UNKNOWN",
    action=Action.PSEUDONYMIZE,
    min_confidence=0.70,
    placeholder_prefix="ENTITY",
)
