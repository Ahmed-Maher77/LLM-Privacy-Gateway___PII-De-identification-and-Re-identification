r"""Deterministic patterns for structured identifiers.

``EMAIL_PATTERN`` is carried over byte-identically from the prototype's
``email_regex.py``.

A note on that pattern, because it has a real and subtle bug: its local-part
character class includes a backtick (it is a legal RFC 5322 atom character), and
the SME transcript wraps every address in markdown code spans. So each match
starts one character early::

    `michael.brown@brightpath-example.com    <- span (5421, 5458)

The pattern is deliberately *not* changed here. The fix belongs in the
aggregation trim step, which strips wrapper characters from every span
regardless of which detector produced it -- so it also fixes ``**FleetCore**``
and ``Ahmed,`` at the same time. Fixing it in the regex would leave the general
class of bug unaddressed.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..entities.taxonomy import EntityType

# ---------------------------------------------------------------------------
# Carried over verbatim from the prototype. Do not edit without updating the
# note above and the test that pins its behaviour.
EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
    r"(?![\w-])"
)
# ---------------------------------------------------------------------------

#: International and grouped national numbers, e.g. ``+44 7700 900123``.
#: Requires either a leading ``+`` or at least three groups, so a meeting
#: timestamp (``0:31``) and a date stamp (``20260924_103012``) cannot match.
PHONE_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?:\+\d{1,3}[ \-.]?)?"
    r"(?:\(\d{1,4}\)[ \-.]?)?"
    r"\d{1,8}(?:[ \-.]\d{1,8}){1,5}"
    # Reject a decimal continuation ("4.6.1") but allow ordinary
    # sentence punctuation, so a number ending a sentence still matches.
    r"(?!\w)(?!\.\d)"
)

#: Negative patterns used to avoid false positives in phone and card detection.
IPV4_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?![\w.])"
)
TIMESTAMP_PATTERN = re.compile(r"(?<![\w.])\d{1,3}:\d{2}(?::\d{2})?(?![\w.])")
IBAN_PATTERN = re.compile(r"(?<![\w-])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[A-Z0-9]{0,4}(?![\w-])")

#: 13-19 digit card numbers with optional separators.
CREDIT_CARD_PATTERN = re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])")

#: A US Social Security number, ``NNN-NN-NNNN``.
SSN_PATTERN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

#: The whole ``user:password@host:port`` authority portion of a connection string.
CONNECTION_STRING_AUTHORITY_PATTERN = re.compile(
    r"(?<=://)(?P<value>[^\s/'\"]+@[^\s/'\"]+)(?=[/\s'\"]|$)"
)

#: ``API_KEY="sk-live-..."`` / ``password: hunter2``.
LABELED_SECRET_PATTERN = re.compile(
    r"(?i:api[_-]?key|secret(?:[_-]?key)?|"
    r"password|passwd|pwd)\s*[:=]\s*[\"']?"
    r"(?P<value>[A-Za-z0-9_\-.!@#$%^&*]{6,})"
)

_PHONE_MIN_DIGITS = 9
_PHONE_MAX_DIGITS = 15


def _digit_count(value: str) -> int:
    return sum(c.isdigit() for c in value)


def iter_phone_matches(text: str) -> Iterator[re.Match[str]]:
    """Phone candidates, with timestamps, IPs and implausible digit counts removed."""
    blocked = {m.span() for m in TIMESTAMP_PATTERN.finditer(text)}
    blocked.update(m.span() for m in IPV4_PATTERN.finditer(text))
    for m in PHONE_PATTERN.finditer(text):
        if any(b_start <= m.start() and m.end() <= b_end for b_start, b_end in blocked):
            continue
        count = _digit_count(m.group())
        if not _PHONE_MIN_DIGITS <= count <= _PHONE_MAX_DIGITS:
            continue
        if m.group().count(".") >= 3:
            continue
        if "+" not in m.group() and not any(c in m.group() for c in " -."):
            continue
        yield m


def iter_credit_card_matches(text: str) -> Iterator[re.Match[str]]:
    """Every card-shaped number, whether or not it passes Luhn, avoiding IBANs."""
    blocked = {m.span() for m in IBAN_PATTERN.finditer(text)}
    for m in CREDIT_CARD_PATTERN.finditer(text):
        if any(b_start <= m.start() and m.end() <= b_end for b_start, b_end in blocked):
            continue
        yield m


# ---------------------------------------------------------------------------
# Deterministic date detection (standard calendar dates, DOB, exp dates)
# ---------------------------------------------------------------------------

_MONTHS = (
    r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
    r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
)

# 1. Day Month Year: e.g. "29 Feb 1964", "29 February 1964", "9 Oct 2026", "22 Sep 2026", "29th of February 1964"
DMY_DATE_PATTERN = re.compile(
    rf"(?<![\w])(?P<day>[0-2]?\d|3[01])(?:st|nd|rd|th)?(?:[ \t]+of)?[ \t]+"
    rf"(?P<month>{_MONTHS})"
    rf"(?:[ \t]*,?[ \t]*(?P<year>(?:19|20)\d{{2}}|\b\d{{2}}\b))?"
    rf"(?![\w])",
    re.IGNORECASE,
)

# 2. Month Day Year: e.g. "April 3, 2025", "September 22, 2026", "April 1st", "Apr 3, 2025", "January 2026"
MDY_DATE_PATTERN = re.compile(
    rf"(?<![\w])(?P<month>{_MONTHS})[ \t]+"
    rf"(?:(?P<day>[0-2]?\d|3[01])(?:st|nd|rd|th)?(?:[ \t]*,?[ \t]*(?P<year>(?:19|20)\d{{2}}))?|(?P<year_only>(?:19|20)\d{{2}}))"
    rf"(?![\w])",
    re.IGNORECASE,
)

# 3. Numeric ISO: YYYY-MM-DD or YYYY/MM/DD
ISO_DATE_PATTERN = re.compile(
    r"(?<![\w])(?P<year>(?:19|20)\d{2})[-/.](?P<month>0[1-9]|1[0-2])[-/.](?P<day>0[1-9]|[12]\d|3[01])(?![\w])"
)

# 4. Numeric DMY or MDY: DD/MM/YYYY or MM/DD/YYYY
NUMERIC_DATE_PATTERN = re.compile(
    r"(?<![\w])(?P<day>0?[1-9]|[12]\d|3[01])[-/.](?P<month>0?[1-9]|1[0-2])[-/.](?P<year>(?:19|20)\d{2})(?![\w])"
)

# 5. Expiration date: e.g. "exp 09/27", "exp: 12/28"
EXP_DATE_PATTERN = re.compile(
    r"(?i:exp(?:ir(?:y|ation))?\.?\s*[:\-]?\s*)(?P<value>(?:0[1-9]|1[0-2])/\d{2})(?![\w])"
)

DATE_PATTERNS = (
    DMY_DATE_PATTERN,
    MDY_DATE_PATTERN,
    ISO_DATE_PATTERN,
    NUMERIC_DATE_PATTERN,
    EXP_DATE_PATTERN,
)


def iter_date_matches(text: str) -> Iterator[re.Match[str]]:
    """Calendar dates, dates of birth, and card expiration dates."""
    seen_spans: list[tuple[int, int]] = []
    for pat in DATE_PATTERNS:
        for m in pat.finditer(text):
            groups = m.groupdict()
            # A lowercase "may" without an explicit 4-digit year is the modal auxiliary verb, not a month
            if groups.get("month") == "may":
                year = groups.get("year") or groups.get("year_only")
                if not year or len(year) != 4:
                    continue
            start, end = m.span("value") if groups.get("value") else m.span()
            if any(s <= start and end <= e for s, e in seen_spans):
                continue
            seen_spans.append((start, end))
            yield m


#: (entity type, compiled pattern or iterator factory, confidence, rule id)
DETERMINISTIC_RULES: tuple[tuple[str, object, float, str], ...] = (
    (EntityType.EMAIL, EMAIL_PATTERN, 0.99, "email"),
    (EntityType.SSN, SSN_PATTERN, 0.95, "ssn"),
    (EntityType.CREDIT_CARD, iter_credit_card_matches, 0.95, "credit_card"),
    (EntityType.PHONE, iter_phone_matches, 0.90, "phone"),
    (EntityType.DATE, iter_date_matches, 0.95, "date"),
    (
        EntityType.CONFIDENTIAL_BUSINESS_INFORMATION,
        CONNECTION_STRING_AUTHORITY_PATTERN,
        0.95,
        "connection_string_authority",
    ),
    (
        EntityType.CONFIDENTIAL_BUSINESS_INFORMATION,
        LABELED_SECRET_PATTERN,
        0.90,
        "labeled_secret",
    ),
)
