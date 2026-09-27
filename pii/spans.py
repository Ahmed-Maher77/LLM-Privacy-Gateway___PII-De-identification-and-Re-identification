"""Entity spans and the rules for resolving overlaps between detectors."""

from __future__ import annotations

from dataclasses import dataclass, field


# Tie-breaker when two detectors claim overlapping text and are the same
# length. Deterministic matches beat the roster and the lexicon, which beat
# the model.
SOURCE_PRIORITY = {
    "pattern": 3,
    "roster": 2,
    "sweep": 2,
    "lexicon": 2,
    "model": 1,
}

# Entity types owned outright by the regex layer. These win an overlap at any
# length, which is what lets a full ADDRESS span displace the model's
# fragmentary guesses at the street name.
AUTHORITATIVE = frozenset({"pattern"})

# Settles two detections of identical text and equal authority. Higher is more
# specific: "987-65-4321" matches both SSN and PHONE, and a social security
# number is the better reading. Without this the winner depended on the order
# rules happened to be appended in, which is not a property worth relying on.
LABEL_PRIORITY: dict[str, int] = {
    "PLACEHOLDER_LITERAL": 99,
    # A credential-bearing URI is one secret. It must outrank the email, URL,
    # IP and phone rules that each match a fragment of the same string.
    "CONNECTION_STRING": 98,
    "CREDENTIAL": 97,
    "EMAIL": 95,
    "URL": 90,
    "IBAN": 88,
    "SWIFT_BIC": 87,
    "EU_VAT": 83,
    "SSN": 86,
    "CREDIT_CARD": 84,
    "ROUTING_NUMBER": 82,
    "BANK_ACCOUNT": 80,
    "PASSPORT": 78,
    "MAC_ADDRESS": 76,
    "IP_ADDRESS": 74,
    "ADDRESS": 72,
    "CARD_EXPIRY": 66,
    "CVV": 64,
    "CUSTOM_ID": 60,
    "DOB": 58,
    "DATE": 55,
    "PHONE": 50,
    "PERSON": 40,
    "JOB_TITLE": 34,
    "MEETING_TITLE": 32,
    "ORG": 30,
    "LOCATION": 20,
}
DEFAULT_LABEL_PRIORITY = 10


@dataclass(frozen=True, slots=True)
class Span:
    """A stretch of the source text that holds a single piece of PII."""

    start: int
    end: int
    label: str
    text: str
    score: float = 1.0
    source: str = "model"
    # Groups surface forms that refer to the same real person or thing, so
    # "Ahmed Farid", "Farid" and "Ahmed F" all collapse onto one placeholder.
    identity: str | None = None

    def __post_init__(self) -> None:
        if self.end <= self.start:
            raise ValueError(f"empty span at {self.start}:{self.end}")

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: Span) -> bool:
        return self.start < other.end and other.start < self.end


@dataclass
class SpanSet:
    """Collects spans from every detector and hands back a conflict-free list."""

    spans: list[Span] = field(default_factory=list)

    def add(self, span: Span) -> None:
        self.spans.append(span)

    def extend(self, spans: list[Span]) -> None:
        self.spans.extend(spans)

    def resolve(self) -> list[Span]:
        """Return non-overlapping spans, ordered by position.

        Weighted interval selection: rank every candidate, then greedily keep
        the best ones that do not collide with something already kept. This is
        what stops a roster match on "lamia" from carving up the middle of
        ``lamia.aly@exampleco.com`` that the email pattern already claimed.
        """
        ranked = sorted(
            self.spans,
            key=lambda s: (
                s.source in AUTHORITATIVE,
                # Longest match wins, so "Lamia Aly" is never displaced by a
                # bare "Lamia" that a later pass also matched.
                s.length,
                SOURCE_PRIORITY.get(s.source, 0),
                LABEL_PRIORITY.get(s.label, DEFAULT_LABEL_PRIORITY),
                # Label specificity outranks score on purpose: PHONE reports a
                # flat 1.0 while a graded CREDIT_CARD may report 0.70, and the
                # card is still the better answer for the same 16 digits.
                s.score,
                # Makes the ordering total, so the result no longer depends on
                # the order detectors happened to append their spans.
                -s.start,
            ),
            reverse=True,
        )

        kept: list[Span] = []
        for candidate in ranked:
            if any(candidate.overlaps(existing) for existing in kept):
                continue
            kept.append(candidate)

        kept.sort(key=lambda s: s.start)
        return kept


def apply_spans(text: str, replacements: list[tuple[Span, str]]) -> str:
    """Splice replacements into ``text`` using offsets.

    Walking back to front keeps every remaining offset valid, and because we
    only ever touch the exact character range a detector reported, no
    substitution can bleed into unrelated words.
    """
    out = text
    for span, placeholder in sorted(replacements, key=lambda item: item[0].start, reverse=True):
        # A name wrapped across a line break is one span, but the line break
        # belongs to the document's layout, not to the name. Put it back.
        newlines = text.count(chr(10), span.start, span.end)
        out = out[: span.start] + placeholder + chr(10) * newlines + out[span.end :]
    return out
