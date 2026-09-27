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
    # Reject a decimal continuation ("4.6.1") but allow ordinary
    # sentence punctuation, so a number ending a sentence still matches.
    r"(?!\w)(?!\.\d)"
)

IPV4_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?![\w.])"
)

#: 13-19 digit card numbers with optional separators. Luhn validity is no
#: longer required for a match -- see ``iter_credit_card_matches`` below.
CREDIT_CARD_PATTERN = re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])")

IBAN_PATTERN = re.compile(r"(?<![\w-])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[A-Z0-9]{0,4}(?![\w-])")

#: ``BP-28491`` or a multi-segment id such as ``CUST-2026-0042``: two-to-six
#: upper-case letters, then one to three ``separator + digits`` groups. The
#: separator is required, which keeps version strings such as ``4.6`` and bare
#: quantities such as ``420`` out.
ACCOUNT_ID_PATTERN = re.compile(r"(?<![\w-])[A-Z]{2,6}(?:[-_/]\d{2,10}){1,3}(?![\w-])")

#: A US Social Security number, ``NNN-NN-NNNN``. Distinctive enough (the exact
#: 3-2-4 digit grouping) not to need a validator.
SSN_PATTERN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

#: A MAC address: six colon- or hyphen-separated hex pairs.
MAC_ADDRESS_PATTERN = re.compile(
    r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])"
)

#: A SWIFT/BIC bank code: 6 letters (bank + country) then 2 or 5 alphanumeric
#: characters (location, optionally a branch). Requiring a digit somewhere in
#: the token is what separates it from an ordinary all-letter acronym or word
#: of the same length -- virtually no English acronym contains a digit, and a
#: dedicated allowlist entry handles the rare one that does.
_SWIFT_SHAPE_RE = re.compile(r"(?<![\w])[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?(?![\w])")

#: ``Routing number: 122000049`` / ``Account number: 9876543210``. Anchored to
#: an explicit label rather than matched by length alone -- a bare run of 6-17
#: digits is far too common a shape (reference numbers, zip+4, quantities) to
#: detect on its own, but the label makes the context unambiguous.
ROUTING_NUMBER_PATTERN = re.compile(
    r"(?i:routing\s*(?:number|no\.?|#))\s*[:\-]?\s*(?P<value>\d{9})(?!\d)"
)
LABELED_ACCOUNT_NUMBER_PATTERN = re.compile(
    r"(?i:account\s*(?:number|no\.?|#))\s*[:\-]?\s*(?P<value>\d{6,17})(?!\d)"
)

#: A timestamp shape that must never be read as a phone number.
TIMESTAMP_PATTERN = re.compile(r"(?<![\w.])\d{1,3}:\d{2}(?::\d{2})?(?![\w.])")

#: The whole ``user:password@host:port`` authority portion of a connection
#: string. Deliberately coarse rather than trying to split user, password and
#: host apart: a password containing its own literal "@" (a realistic and,
#: as this project's own test corpus demonstrated, actually-occurring case)
#: makes precise splitting ambiguous without URL-decoding, and a connection
#: string's password half genuinely being swallowed into a bogus EMAIL match
#: -- while its own prefix leaked in plain text right next to the placeholder
#: -- is exactly the failure this pattern exists to make impossible. Matching
#: (and protecting) the whole authority, host included, is the safe direction
#: to err in for a credentials-bearing string.
CONNECTION_STRING_AUTHORITY_PATTERN = re.compile(
    r"(?<=://)(?P<value>[^\s/'\"]+@[^\s/'\"]+)(?=[/\s'\"]|$)"
)

#: ``API_KEY="sk-live-..."`` / ``password: hunter2``. Anchored to an explicit
#: assignment after a recognised secret-ish label, never to prose mentioning
#: the same words ("the password policy requires..." has no ``:``/``=``
#: right after "password", so it does not match).
LABELED_SECRET_PATTERN = re.compile(
    r"(?i:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|"
    r"password|passwd|pwd)\s*[:=]\s*[\"']?"
    r"(?P<value>[A-Za-z0-9_\-.!@#$%^&*]{6,})"
)

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
    """Every card-shaped number, whether or not it passes Luhn.

    Luhn used to gate this entirely, which meant a card number containing a
    single transcription typo -- or a fictional-but-plausible test number,
    which is exactly what this project's own test corpus turned out to use --
    passed through completely undetected. A card-shaped grouped-digit run is
    distinctive enough on its own that requiring a valid checksum on top of it
    costs more in missed real (or almost-real) numbers than it gains in
    precision, so Luhn validity is no longer a gate, only a fact recorded
    against the match for anyone who wants it.
    """
    yield from CREDIT_CARD_PATTERN.finditer(text)


def iter_swift_matches(text: str) -> Iterator[re.Match[str]]:
    for m in _SWIFT_SHAPE_RE.finditer(text):
        token = m.group()
        if len(token) in (8, 11) and any(ch.isdigit() for ch in token):
            yield m


#: (entity type, compiled pattern or iterator factory, confidence, rule id)
DETERMINISTIC_RULES: tuple[tuple[str, object, float, str], ...] = (
    (EntityType.EMAIL, EMAIL_PATTERN, 0.99, "email"),
    (EntityType.URL, URL_PATTERN, 0.95, "url"),
    (EntityType.IP_ADDRESS, IPV4_PATTERN, 0.95, "ipv4"),
    (EntityType.ACCOUNT_IDENTIFIER, IBAN_PATTERN, 0.90, "iban"),
    (EntityType.ACCOUNT_IDENTIFIER, SSN_PATTERN, 0.95, "ssn"),
    (EntityType.ACCOUNT_IDENTIFIER, MAC_ADDRESS_PATTERN, 0.95, "mac_address"),
    (EntityType.ACCOUNT_IDENTIFIER, iter_swift_matches, 0.90, "swift_bic"),
    (EntityType.ACCOUNT_IDENTIFIER, ROUTING_NUMBER_PATTERN, 0.95, "routing_number"),
    (EntityType.ACCOUNT_IDENTIFIER, LABELED_ACCOUNT_NUMBER_PATTERN, 0.90, "labeled_account_number"),
    (EntityType.CUSTOMER_ID, ACCOUNT_ID_PATTERN, 0.90, "account_id"),
    (EntityType.CREDIT_CARD, iter_credit_card_matches, 0.95, "credit_card"),
    (EntityType.PHONE, iter_phone_matches, 0.90, "phone"),
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
