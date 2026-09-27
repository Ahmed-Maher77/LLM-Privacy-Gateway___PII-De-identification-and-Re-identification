"""Detection-independent scan of the sanitized output.

The original defect this exists to fix: a run reported ``"clean": true`` while
a credit card, a MAC address and four identifiers sat in the output verbatim.
``audit()`` could not have caught them, because it only re-checks values that
were *detected*. It answers "did everything we found get removed?" and is
structurally blind to anything never found.

This module asks the opposite question -- "does anything secret-shaped remain?"
-- with no reference to what was detected. The two are complements:

* ``audit()`` cannot find an undetected MAC address.
* ``scan_residual()`` cannot find the name "Sarah" surviving in prose.

Checksums are deliberately absent here. The card that started all of this
fails Luhn and the routing number fails ABA, so a checksum-gated scanner would
have reproduced the original miss exactly. Shape proposes the candidate;
keyword adjacency decides the severity.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace

from . import patterns

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

_SEVERITY_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    category: str
    severity: str
    confidence: float
    start: int
    end: int
    line: int
    column: int
    text: str  # Raw. Never serialized unless the caller opts in explicitly.
    reason: str
    keyword: str | None = None
    suppressed_by: str | None = None

    @property
    def preview(self) -> str:
        return mask(self.text)

    @property
    def digest(self) -> str:
        return digest(self.text)


def mask(value: str) -> str:
    """Mask a value for display.

    Anything short is masked completely: revealing the first and last character
    of a three-digit CVV or a two-letter state code gives away most of it.
    """
    if len(value) < 6:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def digest(value: str, *, salt: bytes = b"") -> str:
    """Salted short digest, for correlating findings without storing them.

    The salt is not optional in practice. An unsalted SHA-256 of a social
    security number is brute-forceable in about a second -- the whole space is
    10^9 -- so an unsalted digest is not redaction, it is encoding.
    """
    return hashlib.sha256(salt + value.strip().casefold().encode("utf-8")).hexdigest()[:16]


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResidualRule:
    name: str
    pattern: re.Pattern[str]
    category: str
    base_severity: str
    base_confidence: float
    reason: str
    group: int = 0
    validate: Callable[[re.Match[str]], bool] | None = None


SECRET_KEYWORDS = re.compile(
    r"(?i)(card|cvv|cvc|expir\w*|valid\s+thru|routing|aba|account|acct|ssn|"
    r"social\s+security|licen[cs]e|passport|member(?:ship)?|employee|badge|"
    r"policy|patient|iban|swift|pin|token|secret|password|api[_-]?key|mac|ip)"
)
KEYWORD_WINDOW = 40

RESIDUAL_RULES: tuple[ResidualRule, ...] = (
    ResidualRule(
        "card_shape",
        re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])"),
        "FINANCIAL",
        HIGH,
        0.80,
        "payment-card shape, 13-19 digits",
        validate=lambda m: 13 <= len(re.sub(r"\D", "", m.group())) <= 19,
    ),
    ResidualRule(
        "mac",
        re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])"),
        "NETWORK",
        HIGH,
        0.97,
        "IEEE 802 MAC address, six hex pairs",
    ),
    ResidualRule("ssn", patterns.SSN_PATTERN, "GOVERNMENT_ID", HIGH, 0.95, "US SSN shape"),
    ResidualRule("email", patterns.EMAIL_PATTERN, "CONTACT", HIGH, 0.95, "email address"),
    ResidualRule("ipv4", patterns.IPV4_PATTERN, "NETWORK", HIGH, 0.85, "IPv4 address"),
    ResidualRule(
        "jwt",
        re.compile(r"eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}"),
        "CREDENTIAL",
        HIGH,
        0.98,
        "JSON web token",
    ),
    ResidualRule(
        "secret_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|bearer|private[_-]?key)\b"
            r"\s*[:=]\s*[\"']?(?P<value>\S{6,})"
        ),
        "CREDENTIAL",
        HIGH,
        0.90,
        "credential assigned to a secret-named key",
        group=1,
    ),
    ResidualRule(
        "long_digit_run",
        re.compile(r"(?<![\w.-])\d{9,}(?![\w.-])"),
        "IDENTIFIER",
        MEDIUM,
        0.55,
        "nine or more consecutive digits",
    ),
    ResidualRule(
        "labelled_id",
        re.compile(
            r"(?<![\w-])(?P<prefix>[A-Z]{2,6})[-_](?P<body>[A-Z0-9]{3,}(?:[-_][A-Z0-9]+){0,3})"
            r"(?![\w-])"
        ),
        "IDENTIFIER",
        MEDIUM,
        0.60,
        "labelled identifier shape",
        # Share the detection layer's stoplist rather than carrying a second,
        # weaker idea of what an identifier is. Without this, AES-256 and
        # CVE-2024-21762 were reported as identifiers, which forced two
        # documents to "review" and suppressed their entire output -- while
        # the real name leaks in them were graded below these false positives.
        validate=lambda m: any(char.isdigit() for char in m.group("body"))
        and m.group("prefix").casefold() not in patterns.ID_PREFIX_STOPLIST,
    ),
    ResidualRule(
        "snake_id",
        re.compile(r"(?i)(?<!\w)(?:usr|user|acct|cust|emp|mem|sess|tok|key)_[A-Za-z0-9]{4,}(?!\w)"),
        "IDENTIFIER",
        MEDIUM,
        0.60,
        "snake-case identifier with a known prefix",
    ),
    ResidualRule(
        "postal_with_state",
        re.compile(r"\b[A-Z]{2}\s+\d{5}(?:-\d{4})?\b"),
        "LOCATION",
        MEDIUM,
        0.60,
        "US state code followed by a ZIP",
    ),
    ResidualRule(
        "expiry",
        re.compile(r"(?<![\d/])(?:0[1-9]|1[0-2])[/-](?:\d{2}|20\d{2})(?![\d/])"),
        "FINANCIAL",
        LOW,
        0.40,
        "MM/YY shape; a card expiry when a keyword is adjacent",
    ),
    ResidualRule(
        "unredacted_speaker_label",
        # A transcript line whose speaker label is still a name, not a
        # placeholder. Structural, so it catches the whole class regardless of
        # why detection failed -- and it is exactly what was missing when two
        # documents were stamped "clean" with a participant's name in
        # plaintext at every one of their turns.
        # The bracketed timestamp is the discriminator. "Interviewer:" and
        # "Note:" share a plain label's shape and would fire constantly, but a
        # line stamped with a time is a speaker turn and nothing else.
        re.compile(
            r"(?m)^[ \t]*[\[(]\d{1,2}:\d{2}(?::\d{2})?[\])][ \t]*"
            r"(?P<name>(?!\{\{)[^\W\d_][\w'’.\-]*(?:[ \t]+[^\W\d_][\w'’.\-]*){0,3})"
            r"[ \t]*:(?=[ \t]|$)"
        ),
        "CONTACT",
        HIGH,
        0.85,
        "speaker label still carries a name",
        group="name",
        validate=lambda m: "{{" not in m.group("name"),
    ),
    ResidualRule(
        "orphan_number_beside_placeholder",
        re.compile(r"(?<![\w.-])\d{1,6}(?=[ \t]*\{\{)"),
        "LOCATION",
        HIGH,
        0.70,
        "bare number glued to a placeholder, typical of a split address",
    ),
    ResidualRule(
        "high_entropy_hex",
        re.compile(r"(?<!\w)[0-9a-fA-F]{32,}(?!\w)"),
        "CREDENTIAL",
        MEDIUM,
        0.60,
        "long hex string, possibly a hash or key",
    ),
    ResidualRule(
        "high_entropy_b64",
        re.compile(r"(?<![\w+/=])[A-Za-z0-9+/]{24,}={0,2}(?![\w+/=])"),
        "CREDENTIAL",
        MEDIUM,
        0.55,
        "base64-like blob with high entropy",
        validate=lambda m: _shannon_entropy(m.group()) >= 3.5,
    ),
)

ALL_RULES = frozenset(rule.name for rule in RESIDUAL_RULES)


# --------------------------------------------------------------------------
# Suppressors
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Suppressor:
    name: str
    applies: Callable[[Finding, str], bool]
    effect: str  # "drop" | "low" | "medium"


_PLACEHOLDER_SPAN_RE = re.compile(r"\{\{[A-Z][A-Z0-9_]*_\d+\}\}")
_CLOCK_RE = re.compile(r"\d{1,2}:\d{2}(?::\d{2})?\s*(?:[AaPp]\.?[Mm]\.?)?\s*(?:[A-Z]{2,4}T?)?")
_MONEY_LEAD_RE = re.compile(r"[$€£¥]\s*$|\b(?:USD|EUR|GBP|usd|eur|gbp)\s*$")
_MONEY_TRAIL_RE = re.compile(r"^\s*(?:dollars|euros|pounds|USD|EUR|GBP|k\b|M\b|%)")
_QUANTITY_LEAD_RE = re.compile(
    r"(?i)\b(?:about|around|approx\.?|approximately|roughly|~|up\s+to|over|under|"
    r"only|capped\s+at|limit(?:ed)?\s+(?:to|at)|at\s+least|more\s+than|less\s+than)\s*$"
)
_QUANTITY_TRAIL_RE = re.compile(
    r"(?i)^\s*(?:%|percent|ms|s\b|sec|mins?|hours?|days?|weeks?|months?|years?|"
    r"[KMGT]?B\b|users?|people|employees|records?|rows?|items?)"
)
_VERSION_LEAD_RE = re.compile(r"(?i)\b(?:v|version|release|python|node|java|api)\s*$")

_KNOWN_BENIGN = frozenset(
    {
        "4111111111111111",
        "0.0.0.0",
        "127.0.0.1",
        "255.255.255.255",
        "192.168.0.1",
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
    }
)


def _context(text: str, finding: Finding, width: int = KEYWORD_WINDOW) -> tuple[str, str]:
    lead = text[max(0, finding.start - width) : finding.start]
    trail = text[finding.end : finding.end + width]
    return lead, trail


def _inside_placeholder(finding: Finding, text: str) -> bool:
    return any(
        match.start() <= finding.start and finding.end <= match.end()
        for match in _PLACEHOLDER_SPAN_RE.finditer(text)
    )


def _is_year(finding: Finding, text: str) -> bool:
    value = finding.text.strip()
    if not (len(value) == 4 and value.isdigit() and 1900 <= int(value) <= 2099):
        return False
    lead, trail = _context(text, finding)
    return SECRET_KEYWORDS.search(lead) is None and SECRET_KEYWORDS.search(trail) is None


def _is_clock(finding: Finding, text: str) -> bool:
    # A MAC has six hex pairs and cannot be a clock reading, but the shapes are
    # close enough that this needs asserting rather than assuming.
    if finding.rule == "mac":
        return False
    match = _CLOCK_RE.match(text, finding.start)
    return match is not None and match.end() >= finding.end


def _is_money(finding: Finding, text: str) -> bool:
    lead, trail = _context(text, finding, 12)
    return bool(_MONEY_LEAD_RE.search(lead) or _MONEY_TRAIL_RE.match(trail))


def _is_quantity(finding: Finding, text: str) -> bool:
    lead, trail = _context(text, finding, 24)
    return bool(_QUANTITY_LEAD_RE.search(lead) or _QUANTITY_TRAIL_RE.match(trail))


def _is_version(finding: Finding, text: str) -> bool:
    lead, _ = _context(text, finding, 12)
    return bool(_VERSION_LEAD_RE.search(lead))


def _is_bare_expiry(finding: Finding, text: str) -> bool:
    """An MM/YY in prose is a date; after "expires" it is card data."""
    if finding.rule != "expiry":
        return False
    lead, _ = _context(text, finding, 24)
    return re.search(r"(?i)\b(?:exp(?:ir\w*)?|valid\s+thru|good\s+thru|card)\b", lead) is None


SUPPRESSORS: tuple[Suppressor, ...] = (
    Suppressor("placeholder_internal", _inside_placeholder, "drop"),
    Suppressor("clock_time", _is_clock, "drop"),
    Suppressor("year", _is_year, "drop"),
    Suppressor("money", _is_money, "drop"),
    Suppressor("quantity", _is_quantity, "drop"),
    Suppressor("version_number", _is_version, "drop"),
    Suppressor("bare_date", _is_bare_expiry, "drop"),
    Suppressor(
        "known_benign",
        lambda finding, text: finding.text.replace(" ", "").replace("-", "") in _KNOWN_BENIGN
        or finding.text in _KNOWN_BENIGN,
        "low",
    ),
)


@dataclass(frozen=True, slots=True)
class ResidualPolicy:
    enabled_rules: frozenset[str] = ALL_RULES
    ignore_digests: frozenset[str] = frozenset()
    keyword_window: int = KEYWORD_WINDOW
    include_suppressed: bool = False
    key_zones: tuple[tuple[int, int], ...] = field(default=())


DEFAULT_RESIDUAL_POLICY = ResidualPolicy()


def scan_residual(
    sanitized: str,
    *,
    policy: ResidualPolicy = DEFAULT_RESIDUAL_POLICY,
    key_zones: Sequence[tuple[int, int]] = (),
    label_zones: Sequence[tuple[int, int]] = (),
    known_values: Sequence[str] = (),
) -> list[Finding]:
    """Find secret-shaped text surviving in ``sanitized``.

    ``known_values`` are the values ``audit()`` already reported, so a single
    leak is not counted twice under two different names. ``label_zones`` are
    the form-field labels ``DocumentContext`` identified, which share their
    shape with speaker labels and must not be mistaken for one.
    """
    already = {value.strip().casefold() for value in known_values}
    seen: set[tuple[str, int]] = set()
    findings: list[Finding] = []

    for rule in RESIDUAL_RULES:
        if rule.name not in policy.enabled_rules:
            continue
        for match in rule.pattern.finditer(sanitized):
            if rule.validate is not None and not rule.validate(match):
                continue
            start, end = match.span(rule.group)
            if start < 0 or end <= start:
                continue
            if (rule.name, start) in seen:
                continue
            seen.add((rule.name, start))

            value = sanitized[start:end]
            if value.strip().casefold() in already:
                continue
            if digest(value) in policy.ignore_digests:
                continue

            line = sanitized.count("\n", 0, start) + 1
            column = start - (sanitized.rfind("\n", 0, start) + 1)
            lead = sanitized[max(0, start - policy.keyword_window) : start]
            keyword_match = SECRET_KEYWORDS.search(lead)

            severity = rule.base_severity
            confidence = rule.base_confidence
            if keyword_match is not None and severity != HIGH:
                # Shape proposes the candidate; an adjacent keyword is what
                # turns "some digits" into "a routing number".
                severity = HIGH
                confidence = min(1.0, confidence + 0.25)

            finding = Finding(
                rule=rule.name,
                category=rule.category,
                severity=severity,
                confidence=confidence,
                start=start,
                end=end,
                line=line,
                column=column,
                text=value,
                reason=rule.reason,
                keyword=keyword_match.group() if keyword_match else None,
            )
            findings.append(
                _apply_suppressors(finding, sanitized, key_zones, label_zones)
            )

    if not policy.include_suppressed:
        findings = [finding for finding in findings if finding.suppressed_by != "__drop__"]

    findings.sort(key=lambda f: (-_SEVERITY_ORDER[f.severity], f.start))
    return findings


def _apply_suppressors(
    finding: Finding,
    text: str,
    key_zones: Sequence[tuple[int, int]],
    label_zones: Sequence[tuple[int, int]] = (),
) -> Finding:
    """Downgrade or mark a finding, but never discard it silently.

    A suppressed finding keeps ``suppressed_by`` so a reviewer can answer "why
    wasn't X flagged?" as easily as "why was Y?". Silent suppression is how a
    scanner earns the same distrust as the ``clean: true`` it replaced.
    """
    for suppressor in SUPPRESSORS:
        if not suppressor.applies(finding, text):
            continue
        if suppressor.effect == "drop":
            return replace(finding, suppressed_by="__drop__")
        return replace(finding, severity=suppressor.effect, suppressed_by=suppressor.name)

    if any(start < finding.end and finding.start < end for start, end in label_zones):
        # "Interview Title:" and "Note:" have the same shape as a speaker
        # label. DocumentContext already tells them apart by value length, so
        # reuse that rather than inventing a second test here.
        return replace(finding, suppressed_by="__drop__")

    if any(start < finding.end and finding.start < end for start, end in key_zones):
        # A schema key name is not a value.
        return replace(finding, severity=LOW, suppressed_by="structure_key")

    return finding


def severity_counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts = {HIGH: 0, MEDIUM: 0, LOW: 0}
    for finding in findings:
        if finding.suppressed_by == "__drop__":
            continue
        counts[finding.severity] += 1
    return counts


def explain(findings: Sequence[Finding]) -> str:
    """Human-readable report. Values are masked."""
    if not findings:
        return "No residual secret shapes found."
    lines = []
    for finding in findings:
        note = f"  [suppressed by {finding.suppressed_by}]" if finding.suppressed_by else ""
        lines.append(
            f"{finding.severity.upper():6} {finding.rule:34} "
            f"line {finding.line}:{finding.column}  {finding.preview}  "
            f"({finding.reason}){note}"
        )
    return "\n".join(lines)
