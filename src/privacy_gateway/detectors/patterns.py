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

#: http(s) URLs. The trailing class excludes punctuation that commonly follows
#: a URL in prose, so a sentence-ending period is not swallowed.
URL_PATTERN = re.compile(
    r"https?://[A-Za-z0-9\-._~%]+(?::\d{1,5})?"
    r"(?:/[A-Za-z0-9\-._~%!$&'()*+,;=:@/]*)?"
    r"(?:\?[A-Za-z0-9\-._~%!$&'()*+,;=:@/?]*)?"
    r"(?<![.,;:!?`'\"])"
)

#: International and grouped national numbers, e.g. ``+44 7700 900123``.
#: Requires either a leading ``+`` or at least three groups, so a meeting
#: timestamp (``0:31``) and a date stamp (``20260924_103012``) cannot match.
PHONE_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?:\+\d{1,3}[ \-.]?)?"
    r"(?:\(\d{1,4}\)[ \-.]?)?"
    r"\d{2,8}(?:[ \-.]\d{2,8}){1,4}"
    r"(?![\w.])"
)

IPV4_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?![\w.])"
)

#: 13-19 digit card numbers with optional separators; validated by Luhn below.
CREDIT_CARD_PATTERN = re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])")

IBAN_PATTERN = re.compile(r"(?<![\w-])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[A-Z0-9]{0,4}(?![\w-])")

#: ``BP-28491``: two-to-five upper-case letters, a separator, then 3+ digits.
#: The separator is required, which keeps version strings such as ``4.6`` and
#: bare quantities such as ``420`` out.
ACCOUNT_ID_PATTERN = re.compile(r"(?<![\w-])[A-Z]{2,5}[-_/]\d{3,10}(?![\w-])")

#: A timestamp shape that must never be read as a phone number.
TIMESTAMP_PATTERN = re.compile(r"(?<![\w.])\d{1,3}:\d{2}(?::\d{2})?(?![\w.])")

_PHONE_MIN_DIGITS = 9
_PHONE_MAX_DIGITS = 15


def luhn_valid(digits: str) -> bool:
    """Standard Luhn checksum, used to keep card detection precise."""
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 13:
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _digit_count(value: str) -> int:
    return sum(c.isdigit() for c in value)


def iter_phone_matches(text: str) -> Iterator[re.Match[str]]:
    """Phone candidates, with timestamps and implausible digit counts removed."""
    blocked = {m.span() for m in TIMESTAMP_PATTERN.finditer(text)}
    for m in PHONE_PATTERN.finditer(text):
        if m.span() in blocked:
            continue
        if any(b_start <= m.start() and m.end() <= b_end for b_start, b_end in blocked):
            continue
        count = _digit_count(m.group())
        if not _PHONE_MIN_DIGITS <= count <= _PHONE_MAX_DIGITS:
            continue
        # A run of digits with no separator and no country code is far more
        # likely to be an identifier or a quantity than a phone number.
        if "+" not in m.group() and not any(c in m.group() for c in " -."):
            continue
        yield m


def iter_credit_card_matches(text: str) -> Iterator[re.Match[str]]:
    for m in CREDIT_CARD_PATTERN.finditer(text):
        if luhn_valid(m.group()):
            yield m


#: (entity type, compiled pattern or iterator factory, confidence, rule id)
DETERMINISTIC_RULES: tuple[tuple[str, object, float, str], ...] = (
    (EntityType.EMAIL, EMAIL_PATTERN, 0.99, "email"),
    (EntityType.URL, URL_PATTERN, 0.95, "url"),
    (EntityType.IP_ADDRESS, IPV4_PATTERN, 0.95, "ipv4"),
    (EntityType.ACCOUNT_IDENTIFIER, IBAN_PATTERN, 0.90, "iban"),
    (EntityType.CUSTOMER_ID, ACCOUNT_ID_PATTERN, 0.90, "account_id"),
    (EntityType.CREDIT_CARD, iter_credit_card_matches, 0.97, "credit_card_luhn"),
    (EntityType.PHONE, iter_phone_matches, 0.90, "phone"),
)
