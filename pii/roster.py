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
from dataclasses import dataclass

from .context import DocumentContext
from .entities import strip_affixes
from .policy import _normalize, is_name_initial, is_structural_speaker
from .spans import Span

# Transcript exporters disagree on how to mark who is speaking, so match the
# common shapes rather than assuming one tool produced the file.
_NAME = r"(?P<name>[^\W\d_][\w'’.\-]*(?:[ \t]+[^\W\d_][\w'’.\-]*){0,3})"
_TIME = r"\d{1,2}:\d{2}(?::\d{2})?"
_DURATION = (
    r"(?:\d+[ \t]+hours?[ \t]+)?\d+[ \t]+minutes?[ \t]+\d+[ \t]+seconds?"
    r"(?:[ \t]*\d{1,2}:\d{2}(?::\d{2})?)?"
)

SPEAKER_PATTERNS = (
    # "Ahmed Farid   0:31" -- Teams and Zoom exports.
    re.compile(rf"^[ \t]*{_NAME}[ \t]+{_TIME}[ \t]*$", re.MULTILINE),
    # "Ahmed Hamed 1 hour 14 minutes 16 seconds" -- Google Meet / Teams speech transcripts.
    re.compile(rf"^[ \t]*{_NAME}[ \t]+{_DURATION}[ \t]*$", re.MULTILINE),
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


def _is_name_token(token: str) -> bool:
    if not token:
        return False
    if is_name_initial(token[0]):
        return True
    if token.casefold() in NAME_PARTICLES:
        return True
    # Attached particle: "elSharif", "alSabah", "deSilva"
    return any(
        token.lower().startswith(p) and len(token) > len(p) and token[len(p)].isupper()
        for p in NAME_PARTICLES
    )


def _is_title_cased_name(name: str) -> bool:
    """True when every token is capitalised, allowing name particles.

    Speaker labels are title-cased, so this separates "Ahmed Hassan" or
    "Mohamed elSharif" from a heading like "For example" that matches the
    same shape.
    """
    tokens = name.split()
    if not tokens:
        return False
    return all(_is_name_token(token) for token in tokens)


def extract_roster(
    text: str,
    min_turns: int = 2,
    context: DocumentContext | None = None,
) -> list[str]:
    """Return the speakers of a transcript, most frequent first.

    ``min_turns`` guards against a stray line that merely looks like a speaker
    label; a real participant speaks more than once.
    """
    counts: dict[str, int] = {}
    display: dict[str, str] = {}

    last_index = len(SPEAKER_PATTERNS) - 1
    for index, pattern in enumerate(SPEAKER_PATTERNS):
        for match in pattern.finditer(text):
            if (
                index == last_index
                and context is not None
                and context.is_field_label(match.start("name"), match.end("name"))
            ):
                continue
            name = match.group("name").strip()
            if not any(char.isalpha() for char in name) or not _is_title_cased_name(name):
                continue
            if is_structural_speaker(name):
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


# "Raman, Priya" -- a legal appearance list or an index writes the surname
# first. This is a shape match, not a semantic one: it would read "Nairobi,
# Kenya" the same way. That is safe here only because ``_uninvert`` is never
# run over free text -- it is applied exclusively to strings a caller or an
# earlier stage has already asserted are a person's name (a roster entry, a
# ``fixed_names`` entry, a model's own PERSON span), never as a general scan
# of the document.
_INVERTED_NAME_RE = re.compile(
    r"^([A-Z][\w'’-]+),\s+([A-Z][\w'’-]+(?:\s+[A-Z][\w'’-]+)*)$"
)


def _uninvert(name: str) -> str:
    """Rewrite a "Surname, Given" input into "Given Surname".

    Without this, ``strip_affixes`` only rstrips the *last* token, so an
    inverted name's first token keeps its comma and the split lands
    backwards: "Raman," becomes the "first name" and "Priya" the "surname",
    which then poisons every downstream honorific and initial variant.
    """
    match = _INVERTED_NAME_RE.match(name.strip())
    if not match:
        return name
    surname, given = match.groups()
    return f"{given} {surname}"


def name_variants(full_name: str) -> set[str]:
    """Surface forms a person is likely to be referred to by."""
    full_name = _uninvert(full_name)
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
        # The inverted form itself: a document that introduces someone as
        # "Priya Raman" may still index or list them as "Raman, Priya"
        # elsewhere. At well over the bare-surname length, it outranks a
        # lone "Raman" under the longest-first sort in ``propagate_names``,
        # so the comma is swept up with the name instead of being left
        # dangling in the sanitized output.
        variants.add(f"{tokens[-1]}, {tokens[0]}")
    return {variant for variant in variants if len(variant) >= MIN_VARIANT_LENGTH}


@dataclass(frozen=True)
class PropagationTerm:
    """One surface form worth matching everywhere, and how to treat it.

    ``forced`` marks a term whose personhood is asserted by the caller (a
    ``fixed_names`` entry) rather than inferred from the document. It
    bypasses every check in ``propagate_terms`` -- capitalisation, sentence
    position, ``COMMON_WORDS`` -- because none of them need asking once the
    caller has already said "this is a person."

    ``confirmed`` marks a term whose full form is independently known to
    name a real participant -- a roster entry (backed by at least two
    speaker turns) or a name mined from an email address -- as opposed to a
    name only a single detector proposed once. It unlocks two narrower
    relaxations that a merely-proposed name does not get: a common word that
    is also this person's first name may still count when it is not the
    first word of a sentence, and a lowercase occurrence may count on a line
    that has no capitals at all. A name the model *suggested* but nothing
    else corroborates keeps the plain capitalised-single-token rule --
    relaxing it for every model guess would let a mislabelled "Project"
    start propagating through the rest of the document.
    """

    surface: str
    label: str
    identity: str
    forced: bool = False
    confirmed: bool = False


def _is_propagatable(variant: str, *, forced: bool = False) -> bool:
    """Reject single tokens that are really just common words.

    A pre-filter on the *term*, before any text is searched: ``forced`` (or,
    at the call site, ``confirmed``) lets the term through so ``_accept_match``
    can make the real, per-occurrence decision; otherwise a single common
    word is dropped before it can shred a sentence that merely contains it.
    """
    if forced:
        return True
    tokens = variant.split()
    if len(tokens) > 1:
        return True
    return _normalize(variant) not in COMMON_WORDS


# Below this length a lowercase match is indistinguishable from a stray
# short word -- an initial, "ok", "hi" -- even when the roster confirms the
# name it belongs to.
MIN_LOWERCASE_MATCH_LENGTH = 4


def _accept_match(
    term: PropagationTerm,
    matched: str,
    match_start: int,
    context: DocumentContext | None,
) -> bool:
    """Decide whether one regex match is evidence of a person, or of prose.

    Four shapes, each needing a different kind of evidence: a multi-token
    match needs none beyond having matched at all; a capitalised single
    token needs only that; a common word confirmed by the roster additionally
    needs to not be opening a sentence; and a lowercase single token needs
    the roster's confirmation plus a line with no capitals anywhere on it --
    the signature of an ASR transcript turn, not of a sentence that happens
    to mention an ordinary word.
    """
    if term.forced:
        return True

    if len(matched.split()) > 1:
        return True

    is_common = _normalize(matched) in COMMON_WORDS

    if is_name_initial(matched[:1]):
        if not is_common:
            return True
        if not term.confirmed:
            return False
        # The tagger having called this token a proper noun right here
        # overrides the sentence-position veto below: "Will led the
        # meeting." at the start of a paragraph is still evidence, not just
        # a capital that grammar requires.
        if context is not None and context.has_pos and context.pos_at(match_start) == "PROPN":
            return True
        return not (context is not None and context.is_sentence_initial(match_start))

    # A lowercase match.
    if not term.confirmed or is_common or len(matched) < MIN_LOWERCASE_MATCH_LENGTH:
        return False
    return context is not None and context.line_is_lowercase(match_start)


def propagate_terms(
    text: str,
    terms: list[PropagationTerm],
    source: str = "sweep",
    context: DocumentContext | None = None,
) -> list[Span]:
    """Match each term everywhere it occurs in ``text``.

    Detectors fire inconsistently -- a name tagged in one paragraph is missed
    in the next -- so once a term is known to be PII, every occurrence of it is
    redacted. This is what turns partial recall into full coverage.
    """
    spans: list[Span] = []

    for term in terms:
        surface = term.surface
        if not _is_propagatable(surface, forced=term.forced or term.confirmed):
            continue
        # Match across line breaks. re.escape() on the raw surface cannot
        # match a name that a hard-wrapped document split over two lines, so
        # those leaked verbatim, and where propagation did fire it replaced
        # each token separately and emitted the placeholder twice.
        flexible = r"\s+".join(re.escape(part) for part in surface.split())
        pattern = re.compile(rf"(?<!\w){flexible}(?!\w)", re.IGNORECASE)
        for match in pattern.finditer(text):
            matched = match.group()
            if not _accept_match(term, matched, match.start(), context):
                continue
            spans.append(
                Span(
                    start=match.start(),
                    end=match.end(),
                    label=term.label,
                    text=matched,
                    score=1.0,
                    source=source,
                    identity=term.identity,
                    forced=term.forced,
                )
            )

    return spans


def propagate_names(
    text: str,
    names: list[str],
    label: str = "PERSON",
    *,
    forced_names: frozenset[str] = frozenset(),
    confirmed_names: frozenset[str] = frozenset(),
    context: DocumentContext | None = None,
) -> list[Span]:
    """Match every known name -- and its shorthands -- across the whole text.

    Each span carries the canonical full name as its identity, so "Ahmed
    Farid", "Farid" and "Ahmed F" all collapse onto one placeholder.

    ``forced_names`` holds normalized fixed names (see
    ``PIIMiddleware(fixed_names=...)``): every variant of one of these names
    is masked regardless of case or common-word status, because the caller
    has already asserted that surface is a person.

    ``confirmed_names`` holds normalized names independently corroborated by
    the document -- a roster entry backed by real speaker turns, or a name
    mined from an email address -- as opposed to one only a single detector
    proposed. It unlocks the narrower relaxations in ``_accept_match``: a
    common first name may still count outside a sentence's first word, and a
    lowercase occurrence may count on a line with no capitals at all. Passing
    ``context`` is what makes those two checks possible; without it, both
    relaxations fall back to the plain capitalised-single-token rule.
    """
    # Un-invert eagerly, once, before anything below reads a first token as
    # a surname: every dict here is keyed by position (first token, last
    # token), so an inverted input has to be corrected before it is used to
    # build any of them, not just where its own variants are generated.
    names = [_uninvert(name) for name in names]

    terms: list[PropagationTerm] = []
    surname_owners: dict[str, list[str]] = {}
    for full_name in names:
        surname_owners.setdefault(_normalize(full_name.split()[-1]), []).append(full_name)

    # "P. Raman" is short for "Priya Raman": a first initial plus the
    # surname, distinct from the "Ahmed F." shorthand ``name_variants``
    # already generates (that one keeps the first name and abbreviates the
    # surname). Gated on the (initial, surname) pair having one owner, so
    # "R. Pelletier" is not minted when the document also has a "Rupert
    # Pelletier" -- the same unique-ownership standard as the honorific
    # aliases below.
    initial_surname_owners: dict[tuple[str, str], list[str]] = {}
    for full_name in names:
        tokens = full_name.split()
        if len(tokens) < 2 or not tokens[0]:
            continue
        surname = tokens[-1].rstrip(".,;:")
        initial_surname_owners.setdefault(
            (_normalize(tokens[0])[:1], _normalize(surname)), []
        ).append(full_name)

    # Title next to a *full* name, tracked per (title, surname) so the
    # bare-surname pass below can prefer this over guessing from ownership
    # alone: "Dr. Priya Raman" appearing anywhere is better evidence for
    # who "Dr. Raman" means than "only one Raman is in the roster" is.
    confirmed_titles: set[tuple[str, str]] = set()

    for full_name in names:
        identity = f"{label}:{_normalize(strip_affixes(full_name))}"
        forced = _normalize(full_name) in forced_names
        confirmed = forced or _normalize(full_name) in confirmed_names
        for variant in name_variants(full_name):
            terms.append(PropagationTerm(variant, label, identity, forced, confirmed))

        tokens = full_name.split()
        surname = tokens[-1].rstrip(".,;:")
        if len(tokens) > 1 and tokens[0]:
            owner_key = (_normalize(tokens[0])[:1], _normalize(surname))
            if len(initial_surname_owners.get(owner_key, [])) == 1:
                initial = tokens[0][0]
                terms.append(
                    PropagationTerm(f"{initial}. {surname}", label, identity, forced, confirmed)
                )
                terms.append(
                    PropagationTerm(f"{initial} {surname}", label, identity, forced, confirmed)
                )

        # A title next to the *full* name binds unambiguously to this
        # person, whether or not the surname is shared -- "Dr. Priya Raman"
        # is never anyone else. Coverage for the bare "Title Surname" form
        # is handled once per surname below, not per owner here: requiring
        # this loop to see a unique owner before emitting anything left
        # "Ms. Raman" and "Mr. Raman" unmasked whenever two participants
        # shared a surname and the document never wrote a title beside
        # either full name.
        for title in ("Mr.", "Ms.", "Mrs.", "Dr.", "Mr", "Ms", "Mrs", "Dr"):
            title_prefix = rf"(?i)(?<!\w){re.escape(title.rstrip('.'))}\.?[ \t]+"
            full_pattern = re.compile(title_prefix + rf"{re.escape(full_name)}(?!\w)")
            if full_pattern.search(text):
                terms.append(
                    PropagationTerm(f"{title} {surname}", label, identity, forced, confirmed)
                )
                confirmed_titles.add((title, _normalize(surname)))

    # "Title Surname" coverage, once per surname rather than once per person:
    # a bare mention like "Ms. Raman" is masked whether or not that surname
    # has a unique owner. A confirmed (title, surname) pair from above wins;
    # failing that, a unique owner's identity; failing that, the mention
    # gets a title-scoped group identity of its own, so "Ms. Raman" and
    # "Mr. Raman" are never silently merged onto either candidate, and never
    # left as plaintext.
    for norm_surname, owners in surname_owners.items():
        surname = owners[0].split()[-1].rstrip(".,;:")
        for title in ("Mr.", "Ms.", "Mrs.", "Dr.", "Mr", "Ms", "Mrs", "Dr"):
            if (title, norm_surname) in confirmed_titles:
                # Already emitted above, from a "Title FullName" match --
                # better evidence than anything ownership alone can offer.
                continue
            title_prefix = rf"(?i)(?<!\w){re.escape(title.rstrip('.'))}\.?[ \t]+"
            surname_pattern = re.compile(title_prefix + rf"{re.escape(surname)}(?!\w)")
            if not surname_pattern.search(text):
                continue
            if len(owners) == 1:
                owner = owners[0]
                identity = f"{label}:{_normalize(owner)}"
                forced = _normalize(owner) in forced_names
                confirmed = forced or _normalize(owner) in confirmed_names
            else:
                identity = f"{label}:{_normalize(title)} {norm_surname}"
                forced = False
                confirmed = False
            terms.append(
                PropagationTerm(f"{title} {surname}", label, identity, forced, confirmed)
            )

    # Longest first, so a greedy resolver keeps the fullest form.
    terms.sort(key=lambda item: len(item.surface), reverse=True)
    return propagate_terms(text, terms, source="roster", context=context)
