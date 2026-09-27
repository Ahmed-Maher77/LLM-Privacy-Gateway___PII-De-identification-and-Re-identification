"""Normalise detector spans before anything downstream trusts their edges.

Span-boundary drift was the most common defect in the audit and, more
importantly, the most expensive one. It does not stop at cosmetics:

    source:  - Dr. Samuel Adeyemi       Oncology Lead, Sub-Saharan Africa
    span:         "Samuel Adeyemi       Oncology"

Coreference then read "Oncology" as a token of that "full name", folded a
medical specialty and a human being into one identity, and the vault -- which
keeps the longest surface form -- bound the placeholder to the wrong value. One
loose edge became unrecoverable data loss two stages later.

So edges are normalised at the source, before overlap resolution and before any
identity is derived from a span's text.
"""

from __future__ import annotations

import re
import unicodedata

from .context import NON_NAME_POS, DocumentContext
from .spans import Span

# Types whose text must read as a name. Structured identifiers are exempt:
# a MAC address is five colons and an email is full of dots.
NAME_LIKE = frozenset({"PERSON", "ORG", "LOCATION", "JOB_TITLE", "MEETING_TITLE"})

# Pattern spans are matched by shape and their edges are already exact.
EXEMPT_SOURCES = frozenset({"pattern"})

BRACKETS = {"(": ")", "[": "]", "{": "}"}
CLOSERS = {value: key for key, value in BRACKETS.items()}
QUOTES = frozenset("\"'‘’“”")

# Trailing clitics that belong to the sentence, not to the name. Leaving them
# inside the span produced "{{ORG_13}} registered agent" from "Blue Harbor's".
CLITICS = ("'s", "’s", "'S", "’S", "'", "’")

# Longest all-caps token still readable as an acronym rather than a name.
ACRONYM_MAX_LENGTH = 6

# Two or more spaces/tabs: a column boundary in a fixed-width document.
_COLUMN_GAP_RE = re.compile(r"[ 	]{2,}")


def normalize_span(text: str, span: Span, context: DocumentContext | None = None) -> Span | None:
    """Tighten a span's edges, or drop it when nothing defensible remains."""
    if span.source in EXEMPT_SOURCES:
        return span

    start, end = span.start, span.end
    start, end = _strip_outer(text, start, end)
    if span.label in NAME_LIKE:
        start, end = _cut_at_column_gap(text, start, end)
        start, end = _balance(text, start, end)
        start, end = _strip_clitic(text, start, end)
        start, end = _trim_to_capitalised(text, start, end)
    start, end = _strip_outer(text, start, end)

    if end <= start:
        return None

    surface = text[start:end]
    if span.label in NAME_LIKE and not _is_name_like(
        surface, start, end, context, span.label in {"ORG", "LOCATION"}
    ):
        return None

    if (start, end) == (span.start, span.end):
        return span
    return Span(
        start=start,
        end=end,
        label=span.label,
        text=surface,
        score=span.score,
        source=span.source,
        identity=span.identity,
    )


def normalize_spans(
    text: str,
    spans: list[Span],
    context: DocumentContext | None = None,
) -> list[Span]:
    normalized = (normalize_span(text, span, context) for span in spans)
    return [span for span in normalized if span is not None]


# --------------------------------------------------------------------------
# Edge rules
# --------------------------------------------------------------------------


def _strip_outer(text: str, start: int, end: int) -> tuple[int, int]:
    """Drop leading and trailing characters that cannot begin or end a name."""
    while start < end and not (text[start].isalnum() or text[start] in BRACKETS):
        start += 1
    while end > start and not text[end - 1].isalnum():
        end -= 1
    return start, end


def _balance(text: str, start: int, end: int) -> tuple[int, int]:
    """Shrink until brackets and quotes inside the span are balanced.

    "Remote (Zoom Bridge)" was matched as "Remote (Zoom Bridge", swallowing the
    opening parenthesis and stranding the closing one.
    """
    while start < end:
        surface = text[start:end]
        depth = 0
        unmatched_open = -1
        unmatched_close = -1
        for index, char in enumerate(surface):
            if char in BRACKETS:
                if depth == 0:
                    unmatched_open = index
                depth += 1
            elif char in CLOSERS:
                depth -= 1
                if depth < 0:
                    unmatched_close = index
                    break
        if unmatched_close >= 0:
            end = start + unmatched_close
            continue
        if depth > 0 and unmatched_open >= 0:
            end = start + unmatched_open
            continue
        if _unpaired_quotes(surface) % 2 == 1:
            trimmed = next(
                (i for i, ch in enumerate(surface) if _is_quote_at(surface, i)),
                None,
            )
            if trimmed is not None:
                if trimmed == 0:
                    start += 1
                else:
                    end = start + trimmed
                continue
        break
    return start, end


def _cut_at_column_gap(text: str, start: int, end: int) -> tuple[int, int]:
    """End the span at the first run of two or more spaces.

    Fixed-width documents separate columns with padding, and every token either
    side is capitalised, so no capitalisation rule can tell them apart:

        - Dr. Samuel Adeyemi       Oncology Lead, Sub-Saharan Africa

    A person's name never contains a double space, but a column boundary always
    does. A single newline is left alone -- that is a wrapped name, not a new
    column.
    """
    match = _COLUMN_GAP_RE.search(text, start, end)
    return (start, match.start()) if match else (start, end)


def _is_quote_at(surface: str, index: int) -> bool:
    """Is the character at ``index`` acting as a quote rather than a letter?

    An apostrophe between two letters belongs to the word: O'Brien, D'Angelo,
    N'Diaye, don't. Counting those as unbalanced quotes made this function cut
    the span at the apostrophe, so "YUKI TANAKA-O'BRIEN" was redacted as
    "YUKI TANAKA-O" and the surname tail stayed in plaintext on every line the
    speaker appeared.
    """
    char = surface[index]
    if char not in QUOTES:
        return False
    if char in "'’" and 0 < index < len(surface) - 1:
        if surface[index - 1].isalpha() and surface[index + 1].isalpha():
            return False
    return True


def _unpaired_quotes(surface: str) -> int:
    return sum(1 for index in range(len(surface)) if _is_quote_at(surface, index))


def _strip_clitic(text: str, start: int, end: int) -> tuple[int, int]:
    surface = text[start:end]
    for clitic in CLITICS:
        if surface.endswith(clitic) and len(surface) > len(clitic):
            return start, end - len(clitic)
    return start, end


def _is_name_initial(char: str) -> bool:
    """Can this character begin a name?

    Arabic, Hebrew, CJK, Devanagari, Thai and Amharic have no case, so
    ``str.isupper()`` is False for every character in them. Demanding a capital
    would delete every name in such a document outright.
    """
    return char.isupper() or unicodedata.category(char) == "Lo"


def _trim_to_capitalised(text: str, start: int, end: int) -> tuple[int, int]:
    """A name begins and ends on a capitalised token.

    This is what separates "Dubai" from "Dubai warehouse", "Shalaby" from
    "Shalaby project" and "Ahmed Hassan" from "06 - Ahmed Hassan", none of which
    needed a word list to tell apart.
    """
    while start < end:
        if _is_name_initial(text[start]):
            break
        start = _skip_space(text, _token_end(text, start, end), end)
    while end > start:
        token_start = _token_start(text, start, end)
        if token_start < end and _is_name_initial(text[token_start]):
            break
        end = _rstrip_space(text, start, token_start)
    return start, end


def _token_end(text: str, start: int, end: int) -> int:
    index = start
    while index < end and not text[index].isspace():
        index += 1
    return index


def _token_start(text: str, start: int, end: int) -> int:
    index = end
    while index > start and not text[index - 1].isspace():
        index -= 1
    return index


def _skip_space(text: str, index: int, end: int) -> int:
    while index < end and text[index].isspace():
        index += 1
    return index


def _rstrip_space(text: str, start: int, index: int) -> int:
    while index > start and text[index - 1].isspace():
        index -= 1
    return index


def _is_acronym_or_code(
    token: str,
    context: DocumentContext | None = None,
    *,
    uncased_zone: bool = False,
) -> bool:
    """Is this token a code rather than a name?

    Casing alone cannot answer that, which is how "KWAME MENSAH" and
    "JOHN SMITH" came to be deleted as acronyms. Two pieces of document
    evidence settle it:

    * the same word appearing Title Cased somewhere in the document means it
      is a name -- the header writes "Kwame Mensah", so "KWAME" is not an
      acronym;
    * an all-caps line carries no casing information at all, so the test
      stands down there rather than guessing.
    """
    core = "".join(char for char in token if char.isalnum())
    if not core:
        return True
    if any(char.isdigit() for char in core):
        return True
    if len(core) == 1:
        # An initial such as the "M." in "Karen M. Whitfield" cannot be
        # title-cased differently, so it is no evidence either way.
        return False
    if not (core.isupper() and len(core) <= ACRONYM_MAX_LENGTH):
        return False
    if uncased_zone:
        return False
    if context is not None and context.appears_titlecased(core):
        return False
    return True


def _is_name_like(
    surface: str,
    start: int,
    end: int,
    context: DocumentContext | None,
    label_is_org_like: bool = False,
) -> bool:
    """Final sanity check on a normalised name span."""
    if not any(char.isalpha() for char in surface):
        return False

    tokens = surface.split()
    if not tokens:
        return False

    # "ICH E6", "SOC 2", "BX-4471": every token is an acronym or a code, so
    # there is no name here whatever the model called it.
    #
    # A multi-token span additionally needs a digit somewhere before it can be
    # dismissed. Without that condition this rule deleted "KWAME MENSAH",
    # "JOHN SMITH", "ROBERT CHEN JR.", "AMARA NWOSU" and "ROHAN MEHTA" -- every
    # all-caps name whose tokens are all short -- and they leaked as plaintext
    # at roughly 110 sites. In an all-caps speaker label, casing carries no
    # information at all, so it cannot be evidence of acronym-hood there.
    uncased = context.line_is_uncased(start) if context is not None else False
    if all(_is_acronym_or_code(token, context, uncased_zone=uncased) for token in tokens):
        return False

    if context is None:
        return True

    # A form field key is never the data it labels.
    if context.is_field_label(start, end):
        return False

    # The document writes this word in lower case too, so it is probably an
    # ordinary word. Only applied to ORG/LOCATION: surnames like Brown, Mark,
    # Rose and Fields are also common nouns, and a document that happens to
    # contain both would otherwise lose the person. For PERSON this is a
    # negative signal weighed by the corroboration gate, not a veto here.
    if (
        label_is_org_like
        and len(tokens) == 1
        and context.appears_lowercase(tokens[0].strip(".,;:"))
    ):
        return False

    # The tagger sees no proper noun anywhere in the span.
    verdict = context.looks_like_name(start, end)
    if verdict is False:
        return False

    if context.has_pos:
        tags = [context.pos_at(offset) for offset in range(start, end)]
        meaningful = [tag for tag in tags if tag]
        if meaningful and all(tag in NON_NAME_POS for tag in meaningful):
            return False

    return True
