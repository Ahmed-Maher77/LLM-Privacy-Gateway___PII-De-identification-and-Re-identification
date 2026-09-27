"""Transcript structure extraction.

Speaker labels are the single most reliable signal in a meeting transcript, and
they are *structural* -- derived from the document's layout rather than guessed
by a model. That is why the registry detector outranks every statistical layer.

Four formats are recognised:

Teams export::

    Ahmed Farid   0:31
    So.

Markdown minutes::

    **Participants:**
    * Sarah Mitchell - Client Product Manager
    ...
    **09:00 - Ahmed Hassan:**

Inline dialogue, timestamp optional::

    09:00 - Ahmed Hassan: Good morning.
    Sarah Jenkins: Alright everyone, thanks for joining.

Bracketed interview transcript::

    [10:00:10] OLIVIA HARTWELL:
    ---------------------------------------------------------------------
    Good morning, Kwame.

A two-column table row matches the Teams pattern just as well as a real speaker
line does, so a candidate is only accepted when it recurs (>= 2 lines) or is
corroborated by a declared roster. On the real Teams export that yields exactly
six speakers and rejects the header lines.

The inline format requires at least two name tokens (a first and a last name),
never one. A single capitalised word before a colon is indistinguishable from
an ordinary document label -- "Note:", "Date:", "Location:" all have that
shape -- and those labels appear throughout the interview-transcript header
blocks this format also has to coexist with. Requiring two tokens filters out
every such label without costing recall on later bare-first-name mentions:
those are picked up separately by the participant registry's own mention
matching once the person's full name has been seen once, independent of
whether that particular line was recognised as a formal speaker line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

TranscriptFormat = Literal["teams", "markdown", "inline", "bracketed", "unstructured"]

#: ``Ahmed Farid   0:31``: name, two or more spaces, a timestamp, end of line.
#: The name must start and end with a letter, which rejects ``30m 37s`` and
#: ``September 24, 2026, 10:30AM``. The timestamp also accepts a spelled-out
#: ASR duration ("0 minutes 31 seconds"), which needs only one space before it
#: because the suffix shape alone -- digits, "minutes", digits, "seconds",
#: anchored to end of line -- is specific enough not to false-positive on
#: ordinary prose.
TEAMS_SPEAKER_RE = re.compile(
    r"^[ \t]*"
    r"(?P<name>[^\W\d_][^\r\n]{0,58}?[^\W\d_.])"
    r"(?:"
    r"[ \t]{2,}(?P<ts>\d{1,3}:\d{2}(?::\d{2})?)"
    r"|"
    r"[ \t]+(?P<ts_words>\d{1,3}[ \t]+minutes?[ \t]+\d{1,2}[ \t]+seconds?)"
    r")"
    r"[ \t]*$",
    re.MULTILINE | re.UNICODE,
)

#: ``09:00 - Ahmed Hassan: text`` or bare ``Sarah Jenkins: text``. The
#: timestamp-and-dash prefix is optional; the name is not: 2 to 5 capitalised
#: tokens, which is what excludes single-word document labels.
INLINE_SPEAKER_RE = re.compile(
    r"^[ \t]*"
    r"(?:(?P<ts>\d{1,3}:\d{2}(?::\d{2})?)[ \t]*[‐-―-][ \t]*)?"
    r"(?P<name>[A-Z][\w'’.-]*(?:[ \t]+[A-Z][\w'’.-]*){1,4})"
    r":[ \t]+(?P<body>[^\r\n]*)$",
    re.MULTILINE,
)

#: ``[10:00:10] OLIVIA HARTWELL:`` -- a bracketed clock time, then an all-caps
#: name, then a colon, alone on the line. Distinct enough (the leading bracket)
#: that it needs no recurrence floor beyond the shared one.
BRACKETED_SPEAKER_RE = re.compile(
    r"^\[(?P<ts>\d{1,2}:\d{2}(?::\d{2})?)\][ \t]+"
    r"(?P<name>[A-Z][A-Z0-9' .-]{1,58}?):[ \t]*$",
    re.MULTILINE,
)

#: ``**09:00 - Ahmed Hassan:**`` with any dash in the U+2010..U+2015 range.
MD_SPEAKER_RE = re.compile(
    r"^\*\*(?P<ts>\d{1,2}:\d{2})[ \t]*[‐-―\-][ \t]*"
    r"(?P<name>[^:*\r\n]{1,60}?)[ \t]*:\*\*[ \t]*$",
    re.MULTILINE,
)

#: ``* Sarah Mitchell - Client Product Manager`` inside the participants block.
MD_ROSTER_RE = re.compile(
    r"^[ \t]*[*\-+][ \t]+(?P<name>[^‐-―\r\n*]{1,60}?)"
    r"[ \t]*[‐-―][ \t]*(?P<role>[^\r\n]{1,80}?)[ \t]*$",
    re.MULTILINE,
)

_PARTICIPANTS_HEADING_RE = re.compile(
    r"^\**[ \t]*participants?[ \t]*:?\**[ \t]*$", re.MULTILINE | re.IGNORECASE
)

_MAX_NAME_TOKENS = 5


@dataclass(frozen=True, slots=True)
class SpeakerLabel:
    """One occurrence of a speaker's name in a structural position."""

    name: str
    name_start: int
    name_end: int
    line_start: int
    line_end: int
    timestamp: str | None = None


@dataclass(frozen=True, slots=True)
class DeclaredParticipant:
    name: str
    role: str | None
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class Turn:
    index: int
    speaker: SpeakerLabel | None
    body_start: int
    body_end: int


@dataclass(frozen=True, slots=True)
class ParsedTranscript:
    format: TranscriptFormat
    turns: tuple[Turn, ...]
    speaker_labels: tuple[SpeakerLabel, ...]
    declared_participants: tuple[DeclaredParticipant, ...]
    confidence: float

    @property
    def speaker_names(self) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for label in self.speaker_labels:
            seen.setdefault(label.name, None)
        for declared in self.declared_participants:
            seen.setdefault(declared.name, None)
        return tuple(seen)


def _plausible_name(name: str, *, min_tokens: int = 1) -> bool:
    """Reject table rows, timestamps and sentence fragments.

    ``min_tokens=2`` is used by the inline dialogue format, where a single
    capitalised word before a colon is indistinguishable from an ordinary
    document label ("Note:", "Date:", "Location:").
    """
    name = name.strip()
    if not name or len(name) > 60:
        return False
    tokens = name.split()
    if not min_tokens <= len(tokens) <= _MAX_NAME_TOKENS:
        return False
    for token in tokens:
        if token.isdigit():
            return False
        head = token.lstrip("([\"'")
        if not head or not (head[0].isupper() or not head[0].isascii()):
            return False
    return True


class TranscriptParser:
    """Extracts speaker labels, turns and any declared roster."""

    def parse(self, text: str) -> ParsedTranscript:
        fmt, confidence = self.detect_format(text)
        declared: tuple[DeclaredParticipant, ...] = ()
        if fmt == "teams":
            labels = self._teams_labels(text)
        elif fmt == "markdown":
            declared = self._markdown_roster(text)
            labels = self._markdown_labels(text, {d.name for d in declared})
        elif fmt == "inline":
            labels = self._inline_labels(text)
        elif fmt == "bracketed":
            labels = self._bracketed_labels(text)
        else:
            return ParsedTranscript(
                format="unstructured",
                turns=(Turn(0, None, 0, len(text)),),
                speaker_labels=(),
                declared_participants=(),
                confidence=confidence,
            )
        return ParsedTranscript(
            format=fmt,
            turns=self._turns(labels, len(text)),
            speaker_labels=labels,
            declared_participants=declared,
            confidence=confidence,
        )

    # -- format detection ------------------------------------------------
    def detect_format(self, text: str) -> tuple[TranscriptFormat, float]:
        counts: dict[TranscriptFormat, int] = {
            "teams": len(self._teams_labels(text)),
            "markdown": len(MD_SPEAKER_RE.findall(text)),
            "inline": len(self._inline_labels(text)),
            "bracketed": len(self._bracketed_labels(text)),
        }
        best_format = max(counts, key=lambda k: counts[k])
        total = sum(counts.values())
        if counts[best_format] < 3 or total == 0:
            return "unstructured", 0.0
        return best_format, counts[best_format] / total

    # -- teams -----------------------------------------------------------
    def _teams_labels(self, text: str) -> tuple[SpeakerLabel, ...]:
        candidates: list[SpeakerLabel] = []
        counts: dict[str, int] = {}
        for m in TEAMS_SPEAKER_RE.finditer(text):
            name = m.group("name").strip()
            if not _plausible_name(name):
                continue
            start = m.start("name")
            counts[name] = counts.get(name, 0) + 1
            candidates.append(
                SpeakerLabel(
                    name=name,
                    name_start=start,
                    name_end=start + len(name),
                    line_start=m.start(),
                    line_end=m.end(),
                    timestamp=m.group("ts") or m.group("ts_words"),
                )
            )
        # A real speaker speaks more than once; a stray two-column line does not.
        return tuple(c for c in candidates if counts[c.name] >= 2)

    # -- markdown ---------------------------------------------------------
    def _markdown_roster(self, text: str) -> tuple[DeclaredParticipant, ...]:
        heading = _PARTICIPANTS_HEADING_RE.search(text)
        if heading is None:
            return ()
        # Only scan the bullet block immediately after the heading, otherwise
        # every bulleted list in the document is read as a roster.
        block_end = len(text)
        blank = re.compile(r"\n[ \t]*\n[ \t]*(?![*\-+][ \t])")
        m = blank.search(text, heading.end())
        if m is not None:
            block_end = m.start()
        out: list[DeclaredParticipant] = []
        for row in MD_ROSTER_RE.finditer(text, heading.end(), block_end):
            name = row.group("name").strip()
            if _plausible_name(name):
                start = row.start("name")
                out.append(
                    DeclaredParticipant(
                        name=name,
                        role=row.group("role").strip() or None,
                        start=start,
                        end=start + len(name),
                    )
                )
        return tuple(out)

    def _markdown_labels(self, text: str, declared: set[str]) -> tuple[SpeakerLabel, ...]:
        candidates: list[SpeakerLabel] = []
        counts: dict[str, int] = {}
        for m in MD_SPEAKER_RE.finditer(text):
            name = m.group("name").strip()
            if not _plausible_name(name):
                continue
            start = m.start("name")
            counts[name] = counts.get(name, 0) + 1
            candidates.append(
                SpeakerLabel(
                    name=name,
                    name_start=start,
                    name_end=start + len(name),
                    line_start=m.start(),
                    line_end=m.end(),
                    timestamp=m.group("ts"),
                )
            )
        return tuple(c for c in candidates if counts[c.name] >= 2 or c.name in declared)

    # -- inline ------------------------------------------------------------
    def _inline_labels(self, text: str) -> tuple[SpeakerLabel, ...]:
        """2+ token speaker candidates, one entry per matching line.

        Unlike the other three formats, this one applies no recurrence floor.
        A two-person exchange where each speaker is introduced by full name
        exactly once and abbreviated to a bare first name for the rest of the
        conversation (see transcript_test_3.txt) never produces a repeating
        2+ token candidate, so a recurrence requirement would make the format
        permanently undetectable for exactly that shape of document. The
        min_tokens=2 requirement on ``_plausible_name`` already excludes the
        single-word document labels ("Note:", "Date:") that a recurrence
        floor would otherwise exist to filter out; the residual risk -- a
        one-off two-word label such as "Court Reporter:" being registered as
        a spurious participant -- costs an extra placeholder, not a missed
        name, which is the safe direction for a privacy gateway to err in.
        """
        candidates: list[SpeakerLabel] = []
        for m in INLINE_SPEAKER_RE.finditer(text):
            name = m.group("name").strip()
            if not _plausible_name(name, min_tokens=2):
                continue
            start = m.start("name")
            candidates.append(
                SpeakerLabel(
                    name=name,
                    name_start=start,
                    name_end=start + len(name),
                    line_start=m.start(),
                    line_end=m.end("name") + 1,  # after "Name:"; body is inline
                    timestamp=m.group("ts"),
                )
            )
        return tuple(candidates)

    # -- bracketed ----------------------------------------------------------
    def _bracketed_labels(self, text: str) -> tuple[SpeakerLabel, ...]:
        candidates: list[SpeakerLabel] = []
        counts: dict[str, int] = {}
        for m in BRACKETED_SPEAKER_RE.finditer(text):
            name = m.group("name").strip()
            if not _plausible_name(name):
                continue
            start = m.start("name")
            counts[name] = counts.get(name, 0) + 1
            candidates.append(
                SpeakerLabel(
                    name=name,
                    name_start=start,
                    name_end=start + len(name),
                    line_start=m.start(),
                    line_end=m.end(),
                    timestamp=m.group("ts"),
                )
            )
        # The leading bracket already excludes prose false positives, but the
        # recurrence floor is kept for consistency with the other formats.
        return tuple(c for c in candidates if counts[c.name] >= 2)

    # -- turns -------------------------------------------------------------
    def _turns(self, labels: tuple[SpeakerLabel, ...], length: int) -> tuple[Turn, ...]:
        if not labels:
            return (Turn(0, None, 0, length),)
        turns: list[Turn] = []
        if labels[0].line_start > 0:
            turns.append(Turn(0, None, 0, labels[0].line_start))
        for i, label in enumerate(labels):
            end = labels[i + 1].line_start if i + 1 < len(labels) else length
            turns.append(Turn(len(turns), label, label.line_end, end))
        return tuple(turns)
