"""Context-sensitive span validation and repair.

:class:`DetectedEntity` can only enforce invariants that need no access to the
source text. Everything that requires the document lives here, and runs at the
aggregation gate.

The word-alignment rule is the structural defence against sub-word fragments.
The prototype's Hugging Face layer emitted ``"She"`` (of "Hossam"), ``"N"`` (of
"Rania") and ``"Al"`` (of "Aly"); each was then replaced everywhere it occurred.
Here such a span is either expanded to the whole word -- which *improves*
recall -- or dropped.
"""

from __future__ import annotations

import re
from enum import StrEnum

from .entity import DetectedEntity
from .taxonomy import LINE_BOUNDED

#: Characters trimmed from both ends of a span. Markdown emphasis, code
#: backticks, quotes, brackets and trailing punctuation are never part of an
#: entity. This is also the generic fix for ``EMAIL_PATTERN`` matching a
#: leading backtick in ``\u0060michael.brown@example.com\u0060``.
DEFAULT_TRIM_CHARS = " \t\r\n`\"'*_()[]{}<>,;:.!?\u2018\u2019\u201c\u201d\u00ab\u00bb"

_POSSESSIVE_RE = re.compile(r"['\u2019]s$")

#: Filler produced by automatic speech recognition. Statistical detectors label
#: these as names with surprising frequency in noisy transcripts.
ASR_NOISE = frozenset(
    {
        "mm", "mhm", "hmm", "uh", "uhh", "ohh", "oh", "ah", "ahh", "eh",
        "yeah", "yep", "yes", "no", "ok", "okay", "so", "and", "the", "la",
        "bye", "hi", "hey", "hello", "right", "like", "well", "um", "umm",
    }
)


class SpanVerdict(StrEnum):
    VALID = "valid"
    OUT_OF_RANGE = "out_of_range"
    TEXT_MISMATCH = "text_mismatch"
    NOT_WORD_ALIGNED = "not_word_aligned"
    TOO_SHORT = "too_short"
    TOO_LONG = "too_long"
    CROSSES_NEWLINE = "crosses_newline"
    EMPTY_AFTER_TRIM = "empty_after_trim"
    NO_ALNUM = "no_alnum"
    ASR_NOISE = "asr_noise"
    LOW_CONFIDENCE = "low_confidence"
    NOT_PROPER_NOUN = "not_proper_noun"
    COMMON_WORD = "common_word"


def is_word_aligned(text: str, start: int, end: int) -> bool:
    """True when neither edge of the span splits a word.

    A span is misaligned when the character just outside it and the character
    just inside it are both alphanumeric -- i.e. the boundary falls in the
    middle of a token.
    """
    if start < 0 or end > len(text) or end <= start:
        return False
    left_ok = start == 0 or not (text[start - 1].isalnum() and text[start].isalnum())
    right_ok = end == len(text) or not (text[end - 1].isalnum() and text[end].isalnum())
    return left_ok and right_ok


def expand_to_word_boundary(text: str, start: int, end: int) -> tuple[int, int]:
    """Grow a span outwards until both edges sit on a word boundary."""
    while start > 0 and text[start - 1].isalnum() and text[start].isalnum():
        start -= 1
    while end < len(text) and text[end - 1].isalnum() and text[end].isalnum():
        end += 1
    return start, end


def trim_span(
    text: str, start: int, end: int, trim_chars: str = DEFAULT_TRIM_CHARS
) -> tuple[int, int]:
    """Shrink a span past wrapper characters at either end."""
    while start < end and text[start] in trim_chars:
        start += 1
    while end > start and text[end - 1] in trim_chars:
        end -= 1
    return start, end


def strip_possessive(text: str, start: int, end: int) -> tuple[int, int]:
    """Drop a trailing ``'s`` so that ``Sarah's`` yields the span of ``Sarah``."""
    match = _POSSESSIVE_RE.search(text[start:end])
    return (start, end - len(match.group())) if match else (start, end)


def validate_span(
    entity: DetectedEntity,
    text: str,
    *,
    min_chars: int = 2,
    max_chars: int = 96,
    require_word_boundary: bool = True,
) -> SpanVerdict:
    """Classify a span against the canonical text. ``VALID`` means keep it."""
    if entity.start < 0 or entity.end > len(text) or entity.end <= entity.start:
        return SpanVerdict.OUT_OF_RANGE
    if text[entity.start : entity.end] != entity.text:
        return SpanVerdict.TEXT_MISMATCH
    stripped = entity.text.strip()
    if not stripped:
        return SpanVerdict.EMPTY_AFTER_TRIM
    if not any(ch.isalnum() for ch in stripped):
        return SpanVerdict.NO_ALNUM
    if len(stripped) < min_chars:
        return SpanVerdict.TOO_SHORT
    if len(stripped) > max_chars:
        return SpanVerdict.TOO_LONG
    if entity.entity_type in LINE_BOUNDED and "\n" in entity.text:
        return SpanVerdict.CROSSES_NEWLINE
    if require_word_boundary and not is_word_aligned(text, entity.start, entity.end):
        return SpanVerdict.NOT_WORD_ALIGNED
    return SpanVerdict.VALID


def realign(
    entity: DetectedEntity,
    text: str,
    *,
    expand: bool,
    trim_chars: str = DEFAULT_TRIM_CHARS,
    strip_possessives: bool = True,
) -> DetectedEntity | None:
    """Repair a span: trim wrappers, drop possessives, optionally widen to a word.

    Returns ``None`` when the span cannot be salvaged. ``expand`` should be True
    only for detectors whose offsets are known to be approximate (the sub-word
    NER tokenizer, and the semantic layer).
    """
    start, end = entity.start, entity.end
    if start < 0 or end > len(text) or end <= start:
        return None

    start, end = trim_span(text, start, end, trim_chars)
    if end <= start:
        return None
    if strip_possessives and entity.entity_type in LINE_BOUNDED:
        start, end = strip_possessive(text, start, end)
    if end <= start:
        return None

    # Truncate at the first newline rather than discarding outright: the
    # leading portion is usually the real entity.
    if entity.entity_type in LINE_BOUNDED:
        newline = text.find("\n", start, end)
        if newline != -1:
            end = newline
            start, end = trim_span(text, start, end, trim_chars)
            if end <= start:
                return None

    if expand:
        start, end = expand_to_word_boundary(text, start, end)

    if (start, end) == (entity.start, entity.end):
        return entity
    meta = {"realigned_from": (entity.start, entity.end)} if (start, end) != entity.span else {}
    return entity.with_span(start, end, text[start:end]).with_metadata(**meta)


def is_asr_noise(value: str) -> bool:
    return value.strip().strip(".,!?").casefold() in ASR_NOISE
