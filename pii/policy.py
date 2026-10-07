"""What counts as PII, and what is deliberately left alone.

Redaction is a trade-off, not a maximum. Replacing every organisation and
place name with a token strips a meeting transcript of the context the LLM
needs to be useful, while protecting nothing personal -- the company name is
already known to whoever is running this. So entity types are selected by
profile, and well-known products and platforms are never redacted at all.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Container, Iterable, Mapping
from difflib import get_close_matches

# Structured identifiers: always redacted, in every profile.
STRUCTURED_TYPES = frozenset(
    {
        "EMAIL",
        "PHONE",
        "SSN",
        "CREDIT_CARD",
        "CVV",
        "CARD_EXPIRY",
        "ROUTING_NUMBER",
        "IBAN",
        "IP_ADDRESS",
        "MAC_ADDRESS",
        "URL",
        "PASSPORT",
        "BANK_ACCOUNT",
        "CUSTOM_ID",
        "CONNECTION_STRING",
        "CREDENTIAL",
        "EU_VAT",
        "SWIFT_BIC",
        "DOB",
        "ADDRESS",
        "ID",
        "JOB_ID",
    }
)

# Detected (the pattern rules are unchanged), but not personal data on their
# own, so no profile redacts them by default. A meeting's length, a time of
# day and a dollar figure are not identifiers -- "48 minutes" and "9:32 AM"
# were being masked in every profile, which is what prompted splitting these
# out of STRUCTURED_TYPES rather than deciding case by case. A caller who
# genuinely needs them gone passes ``entities={"duration": True}`` (etc.) to
# ``PIIMiddleware``.
OPTIONAL_TYPES = frozenset({"TIME", "AMOUNT", "DURATION"})

PROFILES: dict[str, frozenset[str]] = {
    # Who someone is and how to reach them -- the data that actually
    # identifies a person.
    "balanced": STRUCTURED_TYPES | {"PERSON"},
    # Adds employers and places, for when the transcript itself is sensitive.
    "strict": STRUCTURED_TYPES | {"PERSON", "ORG", "LOCATION"},
    # Contact details and credentials only.
    "minimal": STRUCTURED_TYPES,
}

# Balanced by default: people and structured identifiers.
#
# ORG and LOCATION were 20% of everything redacted and the source of nearly
# every over-redaction -- SOC 2, SonarQube, CloudTrail, Shadow IT, Cortana,
# Microsoft Teams, four human languages, three nationalities. An employer or a
# city is quasi-identifying at most, and chasing that vocabulary with an
# allowlist is a game that never converges. `strict` is one flag away for
# documents where the organisation genuinely is sensitive.
DEFAULT_PROFILE = "balanced"

# Structural vocabulary in legal and interview transcripts. These terms carry
# document meaning, not identity, and must survive even when a model labels
# them as an organisation, location, or identifier.
PROTECTED_TERMS = frozenset(
    {
        "PROCEEDINGS", "APPEARANCES", "EXAMINATION", "DIRECT EXAMINATION",
        "CROSS-EXAMINATION", "REDIRECT", "RECROSS-EXAMINATION", "VOIR DIRE",
        "DEPOSITION", "CERTIFICATE", "CERTIFICATE OF REPORTER",
        "IN THE UNITED STATES DISTRICT COURT", "UNITED STATES DISTRICT COURT",
        "DISTRICT COURT", "Q.", "A.", "BY MR.", "BY MS.", "BY MRS.",
        "BY DR.", "PAGE", "PAGES", "JOB NO.", "EXHIBIT", "CASE NO.",
        "CSR NO.", "REPORTER", "PLAINTIFF", "DEFENDANT", "SECTION",
        "SUBPOENA", "AFFIDAVIT",
    }
)

def is_protected_term(text: str) -> bool:
    """Return whether a span is a known structural/document marker."""
    return " ".join(_normalize(text).split()) in _PROTECTED_KEYS


# Structural speaker labels that mark multi-speaker turns or transcript artifacts,
# not personal names.
STRUCTURAL_SPEAKER_LABELS = frozenset(
    {
        "ALL", "BOTH", "EVERYONE", "UNKNOWN", "CROSSTALK", "INAUDIBLE",
        "THE COURT", "THE WITNESS", "Q", "A",
        "UNIDENTIFIED SPEAKER", "OPERATOR", "CALLER",
    }
)
_SPEAKER_DIGITS_RE = re.compile(r"^SPEAKER\s*\d+$", re.IGNORECASE)


def is_structural_speaker(label: str) -> bool:
    """Return whether a speaker label is non-personal transcript structure."""
    clean = label.strip().rstrip(":").strip()
    if clean.upper() in STRUCTURAL_SPEAKER_LABELS:
        return True
    if _SPEAKER_DIGITS_RE.match(clean):
        return True
    return False

# Redacted under every profile, regardless of what the caller selected.
# Neutralized placeholder literals live here: if the profile filter dropped
# them, the injection defence in vault.py would silently do nothing.
MANDATORY_TYPES = frozenset(
    {
        "PLACEHOLDER_LITERAL",
        # Nationality, ethnicity, religion, political affiliation. Redacted
        # under every profile: this is special-category data, and dropping it
        # from the default alongside ORG and LOCATION would have been a quiet
        # downgrade of protection rather than a context/utility trade.
        "NORP",
        # An organisation whose name contains a participant's name -- a law
        # firm, a medical practice, a single-member company. Printing
        # "{{PERSON_1}}, Esq. (Partner, Whitfield & Barnes)" defeats the
        # redaction outright, so these are never governed by the profile.
        "EPONYMOUS_ORG",
    }
)

# Detected so they win the overlap against ORG, then dropped because they are
# in no profile. A job title is not personal data, but letting the model call
# "HR Operations Specialist" an organisation and mask it destroys the sentence.
NO_REDACT_TYPES = frozenset({"JOB_TITLE", "MEETING_TITLE", "ROLE", "DATE"})

# Products, platforms and tools that NER models routinely mistake for people
# or employers, plus the technical acronyms they mistake for companies. None
# of them identify anybody.
# Deliberately short. Product and vendor vocabulary is open-ended, and the
# 195-entry list this replaces never converged -- every new document brought
# new names. What actually does the work now is computed: short all-caps
# tokens are acronyms (`is_technical_acronym`), words the document also writes
# in lower case are ordinary words (`DocumentContext.appears_lowercase`), and
# ORG/LOCATION are not redacted by default at all.
#
# What remains are the few terms that are none of those: mixed-case product
# names that a model reads as a person, and which would therefore survive the
# acronym rule.
DEFAULT_ALLOWLIST = frozenset(
    """
    github gitlab jira confluence slack teams zoom outlook chrome firefox
    safari cortana alexa siri copilot chatgpt claude gemini okta onedrive
    sharepoint dropbox splunk docker kubernetes composer jenkins postman
    windows linux macos android azure firebase mongodb postgres redis
    google microsoft apple amazon meta openai anthropic mastercard visa
    inline outbound inbound upstream downstream serverless
    """.split()
)

# A long run of allowlisted tokens is more likely a clause than a product name.
MAX_ALLOWLIST_TOKENS = 4

# Legal-form suffixes that mark a genuine company rather than an acronym.
CORPORATE_SUFFIXES = frozenset(
    "inc llc ltd limited plc gmbh corp corporation co sa ag bv nv srl pty llp".split()
)
ACRONYM_MAX_LENGTH = 6


def is_technical_acronym(text: str) -> bool:
    """True for a short all-caps token, which is almost never a company.

    A requirements interview is dense with them -- SME, CASB, SIEM, DLP, MFA,
    CFO -- and the models label every one an organisation. Enumerating them in
    the allowlist is a losing game, and masking them makes the document
    unreadable while protecting nobody. Losing a genuinely short company name
    (IBM, BBC) from the ORG set is the cheaper error: an employer is quasi-
    identifying at most, and people are handled by a different type entirely.
    """
    token = text.strip()
    if not token or " " in token:
        return False
    core = token.replace("-", "").replace(".", "").replace("&", "")
    if not core.isalnum() or not 2 <= len(core) <= ACRONYM_MAX_LENGTH:
        return False
    if not core.isupper():
        return False
    return core.casefold() not in CORPORATE_SUFFIXES


def _normalize(value: str) -> str:
    """Casefold and strip accents and punctuation, for set comparison."""
    decomposed = unicodedata.normalize("NFKD", value)
    stripped = "".join(char for char in decomposed if not unicodedata.combining(char))
    # Collapse whitespace: a name wrapped across a line must key the same as
    # the same name on one line.
    collapsed = re.sub(r"\s+", " ", re.sub(r"[^\w\s]", "", stripped))
    return collapsed.casefold().strip()


_PROTECTED_KEYS = frozenset(" ".join(_normalize(term).split()) for term in PROTECTED_TERMS)


def is_name_initial(char: str) -> bool:
    """Can this character begin a personal name?

    Arabic, Hebrew, CJK, Devanagari, Thai and Amharic have no case, so
    ``str.isupper()`` is False for every character in them.
    """
    return char.isupper() or unicodedata.category(char) == "Lo"


def has_name_initial(text: str) -> bool:
    return any(is_name_initial(char) for char in text)


def allowlist_tokens(terms: Iterable[str]) -> frozenset[str]:
    """Normalize allowlist entries, splitting multi-word ones into tokens."""
    tokens: set[str] = set()
    for term in terms:
        tokens.update(_normalize(term).split())
    return frozenset(tokens)


def is_allowlisted(
    text: str,
    allowlist: Container[str],
    *,
    max_tokens: int = MAX_ALLOWLIST_TOKENS,
    protected: Container[str] = frozenset(),
) -> bool:
    """True when *every* normalized token of ``text`` is allowlisted.

    Matching token-wise rather than on the whole string is what lets
    "Microsoft Teams" through: both words are listed, but the joined string
    never was, so a whole-span lookup could not match it.

    ``protected`` holds the tokens of known participant names. If someone in
    the room is called "Mark Java", the roster wins and the allowlist is
    bypassed -- an allowlist entry must never suppress a real person.
    """
    tokens = _normalize(text).split()
    if not tokens or len(tokens) > max_tokens:
        return False
    if any(token in protected for token in tokens):
        return False
    return all(token in allowlist for token in tokens)


def is_non_personal(
    text: str,
    allowlist: Container[str] = (),
    *,
    protected: Container[str] = frozenset(),
) -> bool:
    """True when this surface form is not personal data.

    One named predicate instead of the decision being spread across the
    middleware, and the thing tests should assert. Membership of the allowlist
    is only one of the ways to be non-personal -- a short all-caps acronym
    qualifies without anyone having written it down, which is why the list
    could shrink from 195 entries to 52 without losing anything.
    """
    if is_technical_acronym(text):
        return True
    return is_allowlisted(text, allowlist, protected=protected)


# Every type the policy layer knows the name of, whether or not any profile
# redacts it by default. Used to validate ``entities`` overrides -- a typo in
# a key must fail loudly, not be silently ignored and leak the type it was
# meant to turn off.
KNOWN_TYPES = frozenset().union(*PROFILES.values()) | MANDATORY_TYPES | NO_REDACT_TYPES | OPTIONAL_TYPES


def _normalize_entity_key(key: str, known: frozenset[str]) -> str:
    """Upper-case and validate a caller-supplied entity type name."""
    normalized = key.strip().upper()
    if normalized not in known:
        valid = ", ".join(sorted(known))
        hint = get_close_matches(normalized, sorted(known), n=1)
        suggestion = f" did you mean {hint[0]!r}?" if hint else ""
        raise ValueError(
            f"unknown entity type {key!r} in entities;{suggestion} expected one of {valid}"
        )
    return normalized


def resolve_types(
    profile: str = DEFAULT_PROFILE,
    entities: Mapping[str, bool] | None = None,
    *,
    custom_labels: frozenset[str] | set[str] = frozenset(),
) -> frozenset[str]:
    """Entity types redacted under ``profile``, with explicit overrides.

    ``entities`` is a layer on top of the profile, not a replacement for it:
    a type the caller does not mention keeps the profile's default --
    ``resolve_types("balanced", {"url": False})`` still redacts ``PERSON``
    and every other structured type, minus ``URL``. Keys are matched
    case-insensitively (``"person"`` and ``"PERSON"`` are the same type) and
    validated against every type this package knows about, plus any
    ``custom_labels`` from a loaded pattern config -- an unrecognised key
    raises rather than being silently ignored, which is the one way this
    knob could turn into an unnoticed leak.

    ``PLACEHOLDER_LITERAL``, ``NORP`` and ``EPONYMOUS_ORG`` (see
    ``MANDATORY_TYPES``) cannot be turned off through ``entities``: they are
    security handling, not a profile choice, and disabling
    ``PLACEHOLDER_LITERAL`` in particular would silently defeat the
    injection defence in ``vault.py``. Trying raises rather than the value
    being quietly reinstated.
    """
    try:
        selected = PROFILES[profile]
    except KeyError:
        valid = ", ".join(sorted(PROFILES))
        raise ValueError(f"unknown profile {profile!r}; expected one of {valid}") from None

    # Custom labels are redacted by construction: a pattern rule loaded from
    # TOML that the profile filter then silently discarded would be the
    # easiest way to ship the feature broken. ``entities`` can still turn one
    # off explicitly, the same as any other type.
    resolved = selected | MANDATORY_TYPES | frozenset(custom_labels)

    if entities:
        known = KNOWN_TYPES | frozenset(custom_labels)
        for raw_key, enabled in entities.items():
            key = _normalize_entity_key(raw_key, known)
            if key in MANDATORY_TYPES and not enabled:
                raise ValueError(
                    f"{key!r} cannot be disabled through entities -- it is "
                    "mandatory security handling, not a profile choice"
                )
            resolved = (resolved | {key}) if enabled else (resolved - {key})

    # NO_REDACT_TYPES are detected so they can win an overlap against a type
    # that *is* redacted, then dropped -- they must never end up in the
    # redacted set, regardless of profile or override.
    return resolved - NO_REDACT_TYPES


def describe_policy(
    profile: str = DEFAULT_PROFILE,
    entities: Mapping[str, bool] | None = None,
    *,
    custom_labels: frozenset[str] | set[str] = frozenset(),
) -> dict:
    """A report-friendly summary of what this policy actually redacts.

    Not just the redacted set: also what is deliberately left alone, and
    which overrides did the work, so an artefact can say *why* a type is or
    is not in scope instead of just printing a set of labels.
    """
    redacted = resolve_types(profile, entities, custom_labels=custom_labels)
    known = KNOWN_TYPES | frozenset(custom_labels)
    overrides = {
        _normalize_entity_key(key, known): bool(value)
        for key, value in (entities or {}).items()
    }
    return {
        "profile": profile,
        "redacted": sorted(redacted),
        "not_redacted": sorted(known - redacted),
        "overrides": overrides,
        "mandatory": sorted(MANDATORY_TYPES),
    }
