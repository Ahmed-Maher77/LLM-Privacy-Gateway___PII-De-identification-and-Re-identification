"""Deterministic pattern detectors.

Structured identifiers should never be left to a statistical model: a regex is
exact, fast and explainable. These run at the highest priority so they win any
overlap against the NER models.

Two principles hold everywhere in this module:

1. **A checksum is a signal, never a gate.** A credit card with a transcription
   typo is still a credit card, and refusing to mask it because Luhn fails is
   the worst thing a redaction system can do -- a false negative is permanent,
   a false positive costs a little context. Checksums raise a score; they never
   veto a match.
2. **Redact the value, not the label.** Keyword-anchored rules capture the
   secret in group 1, so "CVV" stays readable while ``482`` disappears.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass

from .spans import Span

# A match scoring below this is discarded. It is the one place recall and
# precision trade off against each other, so it is a single named constant.
MIN_PATTERN_SCORE = 0.50


@dataclass(frozen=True, slots=True)
class PatternRule:
    """One deterministic detector.

    ``group`` selects which part of the match becomes the span: 0 is the whole
    match, 1 (or a group name) is the captured value, which is how a
    keyword-anchored rule redacts the secret without eating the keyword.
    """

    label: str
    pattern: re.Pattern[str]
    group: int | str = 0
    base_score: float = 1.0
    # Returning None drops the match entirely; that is how arity checks work.
    scorer: Callable[[re.Match[str], str], float | None] | None = None


# --------------------------------------------------------------------------
# Checksums and digit helpers
# --------------------------------------------------------------------------


def luhn_valid(digits: str) -> bool:
    """Standard mod-10 check used by payment cards."""
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def aba_valid(digits: str) -> bool:
    """ABA routing transit checksum (weights 3-7-1, repeated)."""
    if len(digits) != 9:
        return False
    weights = (3, 7, 1) * 3
    return sum(int(char) * weights[index] for index, char in enumerate(digits)) % 10 == 0


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


# --------------------------------------------------------------------------
# Contact and network identifiers
# --------------------------------------------------------------------------

# The backtick is legal in an RFC 5322 local part but in practice only ever
# appears as markdown code fencing around the address, so it is excluded here
# and in URL_PATTERN. Including it swallows the fence into the redacted span.
#
# The final label must be alphabetic. Without that, the host of a connection
# string matched as a domain and "P@ssw0rd2026!@10.0.4.15" was redacted as an
# email -- leaving "P@" and the username in cleartext and mislabelling a
# credential as contact data.
EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
    r"\.[A-Za-z]{2,24}"
    r"(?![\w-])"
)

# A URI carrying credentials is one secret, not several. Matching it whole
# stops the email, URL, IP and phone rules from each taking a bite and leaving
# the password fragmented across the output.
#
# The password itself may contain "@" (it does here), so the user-info group is
# greedy up to the LAST "@" before the host.
CONNECTION_STRING_PATTERN = re.compile(
    r"(?i)(?<![\w-])[a-z][a-z0-9+.-]{2,20}://"
    r"[^\s:@/\"']{1,64}:[^\s/\"']{1,128}@"
    r"[^\s\"'<>]{1,256}"
)

# Credential assigned to a secret-named key: password=..., api_key: "...".
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(?<![\w-])(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token)"
    r"\s*[:=]\s*[\"']?(?P<value>[^\s\"',;}\]]{6,128})"
)

JWT_PATTERN = re.compile(
    r"(?<![\w.-])eyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{4,}){1,2}(?![\w.-])"
)

# "Bearer <token>" -- the scheme name stays, the token does not.
BEARER_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z])Bearer\s+(?P<value>[A-Za-z0-9._~+/-]{16,}=*)(?![\w.-])"
)

URL_PATTERN = re.compile(
    r"\b(?:https?://|www\.)[^\s<>\"'`]+[^\s<>\"'`.,;:!?)\]]",
    re.IGNORECASE,
)

# The trailing lookahead must reject another octet but allow a sentence
# period: "the private network at 10.0.4.15." leaked because "." was banned
# outright, while the same address inside a connection string was masked.
IPV4_PATTERN = re.compile(
    r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\.?\d)(?!\w)"
)

# The backreference forces one consistent separator, so "00:1B-44:11-3A:B7" is
# not a MAC. The hyphen in the boundaries keeps this from overlapping a phone.
MAC_PATTERN = re.compile(
    r"(?<![0-9A-Za-z:.-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}"
    r"[0-9A-Fa-f]{2}(?![0-9A-Za-z:.-])"
)

# The "-" in both boundaries matters: without it this matches the first five
# octets of a hyphenated all-decimal MAC and reports them as a phone number.
PHONE_PATTERN = re.compile(
    r"(?<![\w:-])(?:\+\d{1,3}[\s.-]?)?"
    r"(?:\(\d{1,4}\)[\s.-]?)?"
    r"\d{2,4}(?:[\s.-]\d{2,4}){1,4}"
    r"(?![\w:-])"
)

# North American grouping does not describe the rest of the world. "+49 30
# 1234567" ends in a seven-digit block that the pattern above cannot express,
# so it leaked. A leading "+" makes this specific enough to relax the tail.
INTL_PHONE_PATTERN = re.compile(
    r"(?<![\w:-])\+\d{1,3}"
    r"(?:[\s.-]?\(?\d{1,5}\)?){1,3}"
    r"[\s.-]?\d{3,10}"
    r"(?![\w:-])"
)


# Calendar shapes that a digit-group phone pattern would otherwise claim.
# Six deadlines in an action log came back as {{PHONE_1..6}}.
DATE_PATTERN = re.compile(
    r"(?<![\w:-])(?:"
    r"\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"|(?:0[1-9]|[12]\d|3[01])[/.](?:0[1-9]|1[0-2])[/.]\d{2,4}"
    r"|(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/\d{2,4}"
    r")(?![\w:-])"
)

MONTH_DATE_PATTERN = re.compile(
    r"(?<![A-Za-z])(?:January|February|March|April|May|June|July|August|"
    r"September|October|November|December)\s+\d{1,2}(?:st|nd|rd|th)?"
    r"(?:,\s+\d{4})?(?![A-Za-z])",
    re.IGNORECASE,
)

TIME_PATTERN = re.compile(
    r"(?<![\w:])\d{1,2}:\d{2}\s*(?:AM|PM|a\.m\.|p\.m\.)"
    r"(?:\s+[A-Z]{2,5})?(?![\w:])",
    re.IGNORECASE,
)

AMOUNT_PATTERN = re.compile(
    r"(?<![\w])\$\d{1,3}(?:,\d{3})*(?:\.\d+)?(?![\w])"
)

DURATION_PATTERN = re.compile(
    r"(?<![\w])(?:one|two|three|four|five|six|seven|eight|nine|ten|"
    r"fifteen|twenty|thirty|\d+)\s+(?:minutes?|hours?|days?|weeks?|"
    r"months?|years?)(?![\w])",
    re.IGNORECASE,
)

ROLE_PATTERN = re.compile(
    r"(?<![\w-])(?:CEO|CTO|CFO|COO|CIO|CISO|CHRO|CDO|CPO|CRO|CSO|"
    r"VP\s+of\s+(?:Engineering|Data\s+Science)|Director\s+of\s+Analytics|"
    r"Senior\s+Data\s+Analyst|Paralegal|Expert\s+Witness|Court\s+Reporter)"
    r"(?![\w-])",
    re.IGNORECASE,
)

ORG_COMPOUND_PATTERN = re.compile(
    r"(?<![\w-])[A-Z][A-Za-z]+\s+(?:&|and)\s+[A-Z][A-Za-z]+"
    r"(?:\s+(?:LLP|LLC|Inc\.?|Corp\.?|Ltd\.?|LP))?(?![\w-])"
)

JOB_ID_PATTERN = re.compile(
    r"(?i)(?<![\w-])job[ \t]+no\.?[ \t]*:[ \t]*"
    r"(?P<value>[A-Z0-9]+(?:-[A-Z0-9]+){2,})(?![\w-])"
)

DOCUMENT_ID_PATTERN = re.compile(
    r"(?i)(?<![\w-])(?:exhibit|case[ \t]+no\.?|csr[ \t]+no\.?)"
    r"[ \t:#-]*(?P<value>[A-Z0-9][A-Z0-9:-]{1,24})(?![\w-])"
)

LOCATION_GAZETTEER_PATTERN = re.compile(
    r"(?<![\w-])(?:Oakland|Austin|Berkeley|Emeryville|Sonoma)(?![\w-])"
)


def _score_phone(match: re.Match[str], text: str) -> float | None:
    if DATE_PATTERN.fullmatch(match.group()):
        return None
    count = len(_digits(match.group()))
    # Below 7 it is not a phone number; above 15 it exceeds E.164 and is far
    # more likely to be a card or an account number.
    return 1.0 if 7 <= count <= 15 else None


# --------------------------------------------------------------------------
# Payment card data
# --------------------------------------------------------------------------

# The backreference pins a single separator style, which is what lets a
# non-Luhn number be accepted on shape alone without accepting digit soup.
CARD_GROUPED_PATTERN = re.compile(
    r"(?<![\w-])\d{4}([ -])\d{4}\1\d{4}\1\d{4}(?:\1\d{3})?(?![\w-])"
)
CARD_AMEX_PATTERN = re.compile(r"(?<![\w-])3[47]\d{2}([ -])\d{6}\1\d{5}(?![\w-])")
CARD_BARE_PATTERN = re.compile(r"(?<![\w-])\d{13,19}(?![\w-])")

CARD_IIN_RE = re.compile(r"(?:4|5[1-5]|2[2-7]|3[47]|6011|65|35|30[0-5]|3[689]|62)")
CARD_KEYWORD_RE = re.compile(
    r"(?i:card|visa|mastercard|maestro|amex|american\s+express|discover|"
    r"\bpan\b|credit|debit|\bcc\b|charge|payment)"
)
CARD_CONTEXT_CHARS = 60


def _score_card(match: re.Match[str], text: str) -> float | None:
    """Grade a candidate card by accumulating independent signals.

    The only hard requirement is digit arity. Everything else adds confidence,
    so the single shape that falls below threshold is a bare unchecksummed run
    with no issuer prefix and no payment context -- which is what we want,
    because that is indistinguishable from an ordinary long number.
    """
    digits = _digits(match.group())
    if not 13 <= len(digits) <= 19:
        return None

    score = 0.45
    if match.re is not CARD_BARE_PATTERN:
        score += 0.20
    if CARD_IIN_RE.match(digits):
        score += 0.15
    if luhn_valid(digits):
        score += 0.30
    lead = text[max(0, match.start() - CARD_CONTEXT_CHARS) : match.start()]
    if CARD_KEYWORD_RE.search(lead):
        score += 0.25
    return min(score, 1.0)


# A lazy, bounded, newline-free gap between a keyword and its value. It must
# exclude digits so the gap cannot swallow the value, but allow letters,
# because " is " and " number: " are both ordinary separators.
_GAP = r"[^\d\n]{0,16}?"


def _keyword(alternatives: str) -> str:
    r"""Keyword boundary that ignores underscores.

    ``\b`` treats ``_`` as a word character, so ``\bcode\b`` does not fire
    inside ``employee_code``. A letter-only boundary does.
    """
    return rf"(?<![A-Za-z])(?i:{alternatives})(?![A-Za-z])"


CVV_PATTERN = re.compile(
    _keyword(
        r"cvv2?|cvc2?|cid|security\s+code|card\s+verification(?:\s+(?:code|value|number))?"
    )
    + _GAP
    + r"(\d{3,4})(?!\d)"
)

CARD_EXPIRY_PATTERN = re.compile(
    _keyword(r"exp(?:iry|ires?|iration)?(?:\s+date)?|valid\s+thru|good\s+thru")
    + _GAP
    + r"((?:0[1-9]|1[0-2])\s*[/-]\s*(?:\d{2}|20\d{2}))(?!\d)"
)


# --------------------------------------------------------------------------
# Banking
# --------------------------------------------------------------------------

IBAN_PATTERN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b")

SSN_PATTERN = re.compile(r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])")

ROUTING_PATTERN = re.compile(
    _keyword(r"routing|aba|rtn")
    + r"(?:\s*transit)?(?:\s*(?:number|no\.?|#|code))?"
    + _GAP
    + r"(\d{9})(?!\d)"
)

BANK_ACCOUNT_PATTERN = re.compile(
    _keyword(r"account|acct|a/c|sort\s+code")
    + r"(?:\s*(?:number|no\.?|#))?"
    + _GAP
    + r"(\d[\d -]{5,20}\d)(?!\d)"
)


# ISO 3166 alpha-2 codes used as VAT and BIC country prefixes. EL is Greece's
# VAT code and XI is Northern Ireland's, neither of which is the ISO code.
_EU_VAT_COUNTRIES = (
    r"(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|GB|HR|HU|IE|IT|LT|LU|LV|MT|NL|"
    r"PL|PT|RO|SE|SI|SK|XI|CH|NO)"
)

# "ES-B87654321" and "ESB87654321" are the same number. The hyphenated form is
# what appears in documents; neither reaches the generic CUSTOM_ID rule, whose
# body must start with a digit.
EU_VAT_PATTERN = re.compile(
    r"(?<![\w-])" + _EU_VAT_COUNTRIES + r"-?[0-9A-Z]{8,12}(?![\w-])"
)

# BIC country codes are ISO 3166-1 alpha-2, worldwide. Reusing the EU VAT
# subset meant "CITIUS33" (CITI + US + 33) matched nothing, so the code that
# identifies the bank printed next to the masked bank name.
_ISO_COUNTRY = (
    r"(?:A[DEFGILMOQRSTUWXZ]|B[ABDEFGHIJLMNORSTVWYZ]|C[ACDFGHIKLMNORUVWXYZ]|"
    r"D[EJKMOZ]|E[CEGHRST]|F[IJKMOR]|G[ABDEFGHILMNPQRSTUWY]|H[KMNRTU]|"
    r"I[DELMNOQRST]|J[EMOP]|K[EGHIMNPRWYZ]|L[ABCIKRSTUVY]|"
    r"M[ACDEFGHKLMNOPQRSTUVWXYZ]|N[ACEFGILOPRUZ]|OM|P[AEFGHKLMNRSTWY]|QA|"
    r"R[EOSUW]|S[ABCDEGHIJKLMNORTVXYZ]|T[CDFGHJKLMNORTVWZ]|U[AGMSYZ]|"
    r"V[ACEGINU]|W[FS]|Y[ET]|Z[AMW])"
)
_BIC_BODY = r"[A-Z]{4}" + _ISO_COUNTRY + r"[A-Z0-9]{2}(?:[A-Z0-9]{3})?"

# Keyword-anchored: "SWIFT/BIC code DBEKDEFFXXX" keeps the label, masks the
# code. A bare 8- or 11-character token is too weak a shape to trust alone.
# "The SWIFT BIC is BHRTINBB" -- the two names may sit side by side with a
# space rather than a slash, and a copula may separate the label from the code.
# The case-insensitive flag is scoped to the keywords. A global (?i) reaches
# the BIC body too, and since a BIC is four letters plus a country code plus
# two more, any 8-letter word after "swift" or "bic" then matched: "messages",
# "provider", "database", "platform", "incident" and "customer" were all being
# redacted as bank identifiers.
SWIFT_BIC_LABELLED_PATTERN = re.compile(
    r"(?<![A-Za-z])(?i:swift|bic)(?:[\s/]+(?i:swift|bic))?(?:\s*(?i:code|number))?"
    r"(?![A-Za-z])(?:\s+(?i:is|was|are|were))?[^\w\n]{0,12}"
    r"(?P<value>" + _BIC_BODY + r")(?![\w-])"
)

# Standalone, but only the unambiguous 11-character form with a real country.
SWIFT_BIC_PATTERN = re.compile(
    r"(?<![\w-])[A-Z]{4}" + _ISO_COUNTRY + r"[A-Z0-9]{2}[A-Z0-9]{3}(?![\w-])"
)


def _score_eu_vat(match: re.Match[str], text: str) -> float | None:
    """Require at least one digit, so an all-letter word cannot qualify."""
    value = match.group()
    if not any(char.isdigit() for char in value):
        return None
    lead = text[max(0, match.start() - 40) : match.start()]
    anchored = re.search(r"(?i)\b(?:vat|tax|fiscal|nif|ust|tva)\b", lead) is not None
    return 1.0 if anchored else 0.75


def _score_routing(match: re.Match[str], text: str) -> float | None:
    """A labelled nine-digit number is redacted whether or not ABA agrees."""
    return 0.95 if aba_valid(match.group(1)) else 0.70


def _score_iban(match: re.Match[str], text: str) -> float | None:
    return 1.0 if len(_digits(match.group())) >= 6 else None


# --------------------------------------------------------------------------
# Postal addresses
# --------------------------------------------------------------------------

# Horizontal whitespace only. Plain \s crosses newlines, which in a transcript
# cheerfully joins a timecode on one line to a speaker name three lines below.
_H = r"[ \t]"

# Deliberately excludes the ultra-short ambiguous abbreviations (Aly, Row, Walk,
# Sq, Pl, Ln, Ct, bare St, bare Dr): "Aly" is both a USPS abbreviation for Alley
# and a surname that appears in these transcripts.
_STREET_SUFFIX = (
    r"(?i:Street|St\.|Avenue|Ave\.?|Boulevard|Blvd\.?|Road|Rd\.?|Drive|Lane|Court|"
    r"Circle|Terrace|Place|Parkway|Pkwy\.?|Highway|Hwy\.?|Square|Trail|Loop|"
    r"Crossing|Plaza|Commons|Alley)"
)

_US_STATE = (
    r"(?:A[LKZR]|C[AOT]|DE|FL|GA|HI|I[DLNA]|K[SY]|LA|M[EDAINSOT]|N[EVHJMYCD]|"
    r"OH|OK|OR|PA|RI|S[CD]|T[NX]|UT|V[TA]|W[AVIY]|DC)"
)

# UK postcodes ("SW1A 2AA") are alphanumeric and carry no US state, so a
# US-only tail split "10 Downing Street, Westminster" from "London SW1A 2AA"
# and typed the second half as an organisation.
_UK_POSTCODE = r"[A-Z]{1,2}\d[A-Z\d]?" + _H + r"*\d[A-Z]{2}"

_COUNTRY_TAIL = (
    r"(?i:UK|U\.K\.|United\s+Kingdom|Ireland|Germany|France|Spain|Netherlands|"
    r"Belgium|Italy|Portugal|Sweden|Norway|Denmark|Switzerland|Austria|Poland)"
)

# Each locality token must contain a lowercase letter. Without that, "SW" of
# the postcode "SW1A 2AA" parses as another place name and the address stops
# one token short of its own postcode.
_PLACE_WORD = r"[A-Z][A-Za-z'\u2019-]{0,20}[a-z][A-Za-z'\u2019-]{0,20}"
_LOCALITY = _PLACE_WORD + r"(?:" + _H + r"+" + _PLACE_WORD + r"){0,3}"

# Locality, region and postcode nest so the match degrades gracefully: street
# alone, +locality, +postcode, +country. Both US and UK tails are accepted.
ADDRESS_PATTERN = re.compile(
    r"(?<![\w-])\d{1,6}(?:-\d{1,6})?[A-Za-z]?" + _H + r"+"
    r"(?:(?:N|S|E|W|NE|NW|SE|SW|North|South|East|West)\.?" + _H + r"+)?"
    r"(?:[A-Z][A-Za-z'\u2019-]{1,20}" + _H + r"+){1,4}"
    + _STREET_SUFFIX
    + r"(?![A-Za-z])"
    r"(?:" + _H + r"*,?" + _H + r"*(?i:Apt|Apartment|Suite|Ste|Unit|Fl|Floor|Rm|Room|#)\.?"
    + _H + r"*[\w-]{1,8})?"
    # Up to three comma-separated localities (Westminster, London, ...).
    r"(?:" + _H + r"*," + _H + r"*" + _LOCALITY + r"){0,3}"
    # Then either a UK postcode or a US state (+ optional ZIP).
    r"(?:" + _H + r"*,?" + _H + r"*(?:"
    + _UK_POSTCODE + r"|" + _US_STATE + r"(?![A-Za-z])\.?(?:" + _H + r"+\d{5}(?:-\d{4})?)?"
    r"))?"
    r"(?:" + _H + r"*,?" + _H + r"*" + _COUNTRY_TAIL + r"(?![A-Za-z]))?"
)

# "12 Rue Victor Hugo" -- outside English the street type leads. This set is
# small and finite, which is what separates it from the product-name lists
# this rewrite is removing.
_STREET_PREFIX = (
    r"(?i:Rue|Avenue|Av\.|Boulevard|Bd\.|Impasse|Allee|Allée|Place|Chemin|Quai|"
    r"Calle|Carrer|Avenida|Plaza|Paseo|Via|Viale|Piazza|Corso|"
    r"Straße|Strasse|Str\.|Weg|Gasse|Platz|Ring|"
    r"Rua|Travessa|Laan|Straat|Gracht|Gatan|Vägen|Vej|Gade)"
)

ADDRESS_PREFIXED_PATTERN = re.compile(
    r"(?<![\w-])\d{1,6}(?:[-/]\d{1,6})?[A-Za-z]?" + _H + r"+"
    + _STREET_PREFIX + _H + r"+"
    r"(?:[A-Z][A-Za-z'’-]{1,20}" + _H + r"*){1,4}"
    r"(?:,?" + _H + r"*[A-Z][A-Za-z'’-]{1,20})?"
    r"(?:,?" + _H + r"*\d{4,6})?"
)

PO_BOX_PATTERN = re.compile(
    r"(?i:\bP\.?\s?O\.?\s*Box)[ \t]*(?:No\.?[ \t]*)?\d{1,7}"
    r"(?:[ \t]*,[ \t]*[A-Z][A-Za-z'-]+"
    r"(?:[ \t]*,[ \t]*" + _US_STATE + r"(?![A-Za-z])\.?(?:[ \t]+\d{5}(?:-\d{4})?)?)?)?"
)

_STATE_TAIL_RE = re.compile(r",[ \t]*" + _US_STATE + r"(?![A-Za-z])")
_ZIP_TAIL_RE = re.compile(r"\d{5}(?:-\d{4})?$")


def _score_address(match: re.Match[str], text: str) -> float | None:
    value = match.group()
    score = 0.75
    if _STATE_TAIL_RE.search(value):
        score += 0.15
    if _ZIP_TAIL_RE.search(value.rstrip()):
        score += 0.10
    return min(score, 1.0)


# --------------------------------------------------------------------------
# Labelled organisational identifiers
# --------------------------------------------------------------------------

LABELLED_ID_PATTERN = re.compile(
    r"(?<![\w-])"
    r"(?P<prefix>[A-Za-z][A-Za-z0-9]{1,7})"
    r"(?P<sep>[-_])"
    r"(?P<digits>\d{4,12})"
    r"(?P<suffix>(?P=sep)[A-Za-z0-9]{1,4})?"
    r"(?![\w-])"
)

# "RBI/2023/CYB/0847" -- a slash-delimited regulatory case reference. The
# hyphen/underscore rule above cannot see it, so an internal interview ID was
# masked while the regulator's case number beside it was not.
SLASH_ID_PATTERN = re.compile(
    r"(?<![\w/-])(?P<prefix>[A-Z]{2,6})/(?:[A-Z0-9]{2,8}/){1,4}[A-Z0-9]{2,8}(?![\w/-])"
)


def _score_slash_id(match: re.Match[str], text: str) -> float | None:
    value = match.group()
    if not any(char.isdigit() for char in value):
        return None
    if match.group("prefix").casefold() in ID_PREFIX_STOPLIST:
        return None
    return 0.85

# Standards, algorithms and protocols that look exactly like an internal ID.
ID_PREFIX_STOPLIST = frozenset(
    """
    rfc iso iec ansi ieee utf ucs ascii aes des rsa sha md crc http tls ssl
    cve cwe cvss nist pci dss soc fips ecma jsr pep ec2 s3 k8s covid sars
    utc gmt est pst fy rev ver es base jwt oauth saml ldap smtp imap ftp ssh
    tcp udp dns dhcp vlan vpn wpa wep gsm lte rj cat cidr asn win py
    """.split()
)

ID_ANCHOR_RE = re.compile(
    r"(?<![A-Za-z])(?i:id|ids|no\.?|number|code|badge|licen[cs]e|member(?:ship)?|"
    r"employee|account|user|ref(?:erence)?|case|policy|ticket|record|patient|"
    r"customer|client|claim|file)(?![A-Za-z])"
)
ID_CONTEXT_CHARS = 48


def _score_labelled_id(match: re.Match[str], text: str) -> float | None:
    """Score an ID-shaped token, rejecting the standards and acronym lookalikes.

    Four stacked filters, each removing a class the others cannot: digit arity
    kills ``UTF-8`` and ``COVID-19``; the stoplist kills ``RFC-2616``; requiring
    an uppercase prefix for hyphenated IDs kills the open-ended English-word
    class (``Section-1234``); the year rule kills ``Q3-2026``.
    """
    prefix = match.group("prefix")
    separator = match.group("sep")
    digits = match.group("digits")
    suffix = match.group("suffix")

    if prefix.casefold() in ID_PREFIX_STOPLIST:
        return None
    # Hyphenated IDs are written in caps; snake_case ones are not.
    if separator == "-" and not prefix.isupper():
        return None

    lead = text[max(0, match.start() - ID_CONTEXT_CHARS) : match.start()]
    anchored = ID_ANCHOR_RE.search(lead) is not None

    # A bare four-digit tail in the calendar range is a year, not an ID.
    if len(digits) == 4 and 1900 <= int(digits) <= 2099 and not suffix and not anchored:
        return None

    score = 0.55
    if suffix:
        score += 0.15
    if anchored:
        score += 0.25
    if len(digits) >= 6:
        score += 0.10
    return min(score, 1.0)


# --------------------------------------------------------------------------
# Rule table
# --------------------------------------------------------------------------

BUILTIN_RULES: tuple[PatternRule, ...] = (
    # Credentials first. These are long and authoritative, so they win the
    # overlap against the email, URL, IP and phone rules that would otherwise
    # each claim a fragment of the same connection string.
    PatternRule("CONNECTION_STRING", CONNECTION_STRING_PATTERN),
    PatternRule("CREDENTIAL", SECRET_ASSIGNMENT_PATTERN, group="value"),
    PatternRule("CREDENTIAL", BEARER_PATTERN, group="value"),
    PatternRule("CREDENTIAL", JWT_PATTERN),
    PatternRule("EMAIL", EMAIL_PATTERN),
    PatternRule("URL", URL_PATTERN),
    PatternRule("IP_ADDRESS", IPV4_PATTERN),
    PatternRule("MAC_ADDRESS", MAC_PATTERN),
    PatternRule("SSN", SSN_PATTERN),
    PatternRule("IBAN", IBAN_PATTERN, scorer=_score_iban),
    PatternRule("CREDIT_CARD", CARD_GROUPED_PATTERN, scorer=_score_card),
    PatternRule("CREDIT_CARD", CARD_AMEX_PATTERN, scorer=_score_card),
    PatternRule("CREDIT_CARD", CARD_BARE_PATTERN, scorer=_score_card),
    PatternRule("CVV", CVV_PATTERN, group=1),
    PatternRule("CARD_EXPIRY", CARD_EXPIRY_PATTERN, group=1),
    PatternRule("ROUTING_NUMBER", ROUTING_PATTERN, group=1, scorer=_score_routing),
    PatternRule("BANK_ACCOUNT", BANK_ACCOUNT_PATTERN, group=1),
    PatternRule("EU_VAT", EU_VAT_PATTERN, scorer=_score_eu_vat),
    PatternRule("SWIFT_BIC", SWIFT_BIC_LABELLED_PATTERN, group="value"),
    PatternRule("SWIFT_BIC", SWIFT_BIC_PATTERN, base_score=0.75),
    PatternRule("ADDRESS", ADDRESS_PATTERN, scorer=_score_address),
    PatternRule("ADDRESS", ADDRESS_PREFIXED_PATTERN, base_score=0.85),
    PatternRule("ADDRESS", PO_BOX_PATTERN),
    PatternRule("CUSTOM_ID", LABELLED_ID_PATTERN, scorer=_score_labelled_id),
    PatternRule("CUSTOM_ID", SLASH_ID_PATTERN, scorer=_score_slash_id),
    PatternRule("JOB_ID", JOB_ID_PATTERN, group="value"),
    PatternRule("ID", DOCUMENT_ID_PATTERN, group="value"),
    PatternRule("DATE", DATE_PATTERN),
    PatternRule("DATE", MONTH_DATE_PATTERN),
    PatternRule("TIME", TIME_PATTERN),
    PatternRule("AMOUNT", AMOUNT_PATTERN),
    PatternRule("DURATION", DURATION_PATTERN),
    PatternRule("ROLE", ROLE_PATTERN),
    PatternRule("ORG", ORG_COMPOUND_PATTERN),
    PatternRule("LOCATION", LOCATION_GAZETTEER_PATTERN),
    PatternRule("PHONE", INTL_PHONE_PATTERN, scorer=_score_phone),
    PatternRule("PHONE", PHONE_PATTERN, scorer=_score_phone),
)


def _spans_for_rule(rule: PatternRule, text: str, min_score: float) -> Iterator[Span]:
    for match in rule.pattern.finditer(text):
        start, end = match.span(rule.group)
        # An optional group that did not participate reports (-1, -1), and a
        # zero-width match would raise out of Span. Neither should reach it.
        if start < 0 or end <= start:
            continue

        score = rule.base_score if rule.scorer is None else rule.scorer(match, text)
        if score is None or score < min_score:
            continue

        yield Span(
            start=start,
            end=end,
            label=rule.label,
            text=text[start:end],
            score=min(float(score), 1.0),
            source="pattern",
        )


def detect_patterns(
    text: str,
    *,
    rules: Sequence[PatternRule] | None = None,
    min_score: float = MIN_PATTERN_SCORE,
) -> list[Span]:
    """Find every structured identifier in ``text``."""
    spans: list[Span] = []
    for rule in BUILTIN_RULES if rules is None else rules:
        spans.extend(_spans_for_rule(rule, text, min_score))
    return spans
