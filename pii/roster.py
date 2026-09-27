"""Roster-driven name propagation.

The single biggest recall win on meeting transcripts. Speaker labels give a
reliable roster of who is in the room; once a person is known, every later
mention of them -- first name only, surname only, a stray "Ahmed F" -- can be
matched deterministically instead of hoping the NER model fires again.

This is what closes the leak where "Lamia" survived 57 times in plaintext
because the model only ever tagged the full "Lamia Aly".
"""

from __future__ import annotations

import re

from .policy import _normalize
from .spans import Span

# Transcript exporters disagree on how to mark who is speaking, so match the
# common shapes rather than assuming one tool produced the file.
_NAME = r"(?P<name>[^\W\d_][\w'’.\-]*(?:[ \t]+[^\W\d_][\w'’.\-]*){0,3})"
_TIME = r"\d{1,2}:\d{2}(?::\d{2})?"

SPEAKER_PATTERNS = (
    # "Ahmed Farid   0:31" -- Teams and Zoom exports.
    re.compile(rf"^[ \t]*{_NAME}[ \t]+{_TIME}[ \t]*$", re.MULTILINE),
    # "**09:00 - Ahmed Hassan:**" -- timecode first, markdown-wrapped.
    re.compile(rf"^[ \t]*\**{_TIME}[ \t]*[-–—][ \t]*{_NAME}\**[ \t]*:", re.MULTILINE),
    # "[14:31:02] JAMES O'CONNOR:" -- bracketed timestamp, a very common
    # export format. Without this the roster came back empty on every one of
    # four transcripts, so the most reliable signal in a transcript -- whoever
    # speaks is a participant -- went unused and their names leaked.
    re.compile(rf"^[ \t]*[\[(]{_TIME}[\])][ \t]*{_NAME}[ \t]*:", re.MULTILINE),
    # "Ahmed Hassan:" / "**Ahmed Hassan:**" -- plain speaker labels.
    re.compile(rf"^[ \t]*\**{_NAME}\**[ \t]*:(?![\d/])", re.MULTILINE),
)

# Capitalised tokens that are ordinary words far more often than they are
# names. Propagating these alone would shred the transcript.
# Trimmed from 137 entries. These guard single-token roster propagation --
# a first name that is also an everyday word -- which is the one place no
# computed signal helps, because the token is capitalised at a sentence start
# and the document may never write it in lower case.
COMMON_WORDS = frozenset(
    """
    a an and are as at be but by for from he her him his i if in is it its me
    my no not of on or our she so that the their them then there these they
    this to us was we were what when where which who why will with you your
    yes ok okay right sure thanks hi hello hey bye good great well like just
    now today tomorrow yesterday next last week month year day time meeting
    call team project task update status sorry sir mr mrs ms dr prof
    """.split()
)

MIN_VARIANT_LENGTH = 3

# Lowercase particles that legitimately appear inside a name.
NAME_PARTICLES = frozenset(
    {"de", "del", "der", "van", "von", "da", "das", "dos", "la", "le", "bin", "al", "el"}
)


def rejoin_split_names(text: str) -> str:
    """Join a conservative two-token capitalized name across one newline."""
    pattern = re.compile(
        r"(?<![\w])([A-Z][a-z'’-]{2,})(\n)([A-Z][a-z'’-]{2,})(?![\w])"
    )

    def replace(match: re.Match[str]) -> str:
        before = text[: match.start()]
        if before.rstrip().endswith((".", "!", "?", ":", ";")):
            return match.group(0)
        return f"{match.group(1)} {match.group(3)}"

    return pattern.sub(replace, text)


def _is_title_cased_name(name: str) -> bool:
    """True when every token is capitalised, allowing name particles.

    Speaker labels are title-cased, so this separates "Ahmed Hassan" from a
    heading like "For example" that matches the same shape.
    """
    tokens = name.split()
    if not tokens:
        return False
    return all(
        token[0].isupper() or token.casefold() in NAME_PARTICLES for token in tokens
    )


def extract_roster(text: str, min_turns: int = 2) -> list[str]:
    """Return the speakers of a transcript, most frequent first.

    ``min_turns`` guards against a stray line that merely looks like a speaker
    label; a real participant speaks more than once.
    """
    counts: dict[str, int] = {}
    display: dict[str, str] = {}

    for pattern in SPEAKER_PATTERNS:
        for match in pattern.finditer(text):
            name = match.group("name").strip()
            if not any(char.isalpha() for char in name) or not _is_title_cased_name(name):
                continue
            key = _normalize(name)
            # Section headings ("Summary:", "Date:") look exactly like speaker
            # labels, so anything made only of everyday words is discarded.
            if not key or all(token in COMMON_WORDS for token in key.split()):
                continue
            counts[key] = counts.get(key, 0) + 1
            display.setdefault(key, name)

    confirmed = [key for key, count in counts.items() if count >= min_turns]
    confirmed.sort(key=lambda key: counts[key], reverse=True)
    return [display[key] for key in confirmed]


def name_variants(full_name: str) -> set[str]:
    """Surface forms a person is likely to be referred to by."""
    from .entities import strip_affixes

    tokens = [token for token in re.split(r"\s+", strip_affixes(full_name)) if token]
    if not tokens:
        return set()

    variants = {full_name.strip()}
    if len(tokens) > 1:
        variants.add(" ".join(tokens))
        # First name, surname, and "First L." style shorthands.
        variants.add(tokens[0])
        variants.add(tokens[-1])
        # Legal names often appear once with a middle name and later without
        # it. Both forms refer to the same participant.
        if len(tokens) > 2:
            variants.add(f"{tokens[0]} {tokens[-1]}")
        if len(tokens[-1]) > 1 and tokens[-1][1].isalpha():
            variants.add(f"{tokens[0]} {tokens[-1][0]}")
            variants.add(f"{tokens[0]} {tokens[-1][0]}.")
    return {variant for variant in variants if len(variant) >= MIN_VARIANT_LENGTH}


def _is_propagatable(variant: str) -> bool:
    """Reject single tokens that are really just common words."""
    tokens = variant.split()
    if len(tokens) > 1:
        return True
    return _normalize(variant) not in COMMON_WORDS


def propagate_terms(
    text: str,
    terms: list[tuple[str, str, str]],
    source: str = "sweep",
) -> list[Span]:
    """Match each ``(surface, label, identity)`` term everywhere in ``text``.

    Detectors fire inconsistently -- a name tagged in one paragraph is missed
    in the next -- so once a term is known to be PII, every occurrence of it is
    redacted. This is what turns partial recall into full coverage.
    """
    spans: list[Span] = []

    for surface, label, identity in terms:
        if not _is_propagatable(surface):
            continue
        # Match across line breaks. re.escape() on the raw surface cannot
        # match a name that a hard-wrapped document split over two lines, so
        # those leaked verbatim, and where propagation did fire it replaced
        # each token separately and emitted the placeholder twice.
        flexible = r"\s+".join(re.escape(part) for part in surface.split())
        pattern = re.compile(rf"(?<!\w){flexible}(?!\w)", re.IGNORECASE)
        for match in pattern.finditer(text):
            matched = match.group()
            # A single token only counts when capitalised in the text, which
            # keeps ordinary prose words out of the redaction set.
            if len(surface.split()) == 1 and not matched[0].isupper():
                continue
            spans.append(
                Span(
                    start=match.start(),
                    end=match.end(),
                    label=label,
                    text=matched,
                    score=1.0,
                    source=source,
                    identity=identity,
                )
            )

    return spans


def propagate_names(
    text: str,
    names: list[str],
    label: str = "PERSON",
) -> list[Span]:
    """Match every known name -- and its shorthands -- across the whole text.

    Each span carries the canonical full name as its identity, so "Ahmed
    Farid", "Farid" and "Ahmed F" all collapse onto one placeholder.
    """
    terms: list[tuple[str, str, str]] = []
    surname_owners: dict[str, list[str]] = {}
    for full_name in names:
        surname_owners.setdefault(_normalize(full_name.split()[-1]), []).append(full_name)
    for full_name in names:
        identity = f"{label}:{_normalize(full_name)}"
        for variant in name_variants(full_name):
            terms.append((variant, label, identity))

        # Add honorific aliases only when the document supplies that title
        # beside this surname. This keeps "Ms. Halloran" and "Mr. Halloran"
        # distinct when two participants share a surname.
        surname = full_name.split()[-1].rstrip(".,;:")
        for title in ("Mr.", "Ms.", "Mrs.", "Dr.", "Mr", "Ms", "Mrs", "Dr"):
            title_prefix = rf"(?i)(?<!\w){re.escape(title.rstrip('.'))}\.?[ \t]+"
            full_pattern = re.compile(title_prefix + rf"{re.escape(full_name)}(?!\w)")
            surname_pattern = re.compile(title_prefix + rf"{re.escape(surname)}(?!\w)")
            if full_pattern.search(text) or (
                len(surname_owners.get(_normalize(surname), [])) == 1
                and surname_pattern.search(text)
            ):
                terms.append((f"{title} {surname}", label, identity))

    # Longest first, so a greedy resolver keeps the fullest form.
    terms.sort(key=lambda item: len(item[0]), reverse=True)
    return propagate_terms(text, terms, source="roster")
