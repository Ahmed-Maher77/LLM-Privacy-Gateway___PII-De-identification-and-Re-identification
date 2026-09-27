"""Participant registry: structural names, reused across the whole document.

A speaker label is ground truth, so once ``Ahmed Farid`` has been seen heading a
turn, every later mention of that name is a high-confidence PERSON -- no model
inference required. This is what stops a noisy-ASR transcript from depending on
a statistical detector to recognise its own participants.

**Ambiguity is never resolved.** ``pod_meeting.txt`` has three Ahmeds (Farid,
Hamed and Maher), so a bare "Ahmed" cannot be attributed. It gets its own
placeholder that restores to exactly ``"Ahmed"``. Guessing "the most recent
speaker" would be wrong about two thirds of the time, and being wrong means the
*final output* attributes a sentence to someone who did not say it -- a worse
and far less auditable failure than the one the gateway is fixing. The
candidate list is recorded in metadata so a reviewer can see the ambiguity.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Literal

from .transcript import ParsedTranscript

MentionKind = Literal["speaker_label", "full_name", "alias", "token"]

#: Single tokens that are common English words or ASR filler and must never be
#: treated as a participant reference, even when someone is called "Mark".
TOKEN_STOPWORDS = frozenset(
    {
        "the", "and", "for", "but", "not", "you", "are", "was", "were", "this",
        "that", "with", "from", "have", "has", "had", "will", "can", "all",
        "any", "one", "two", "new", "now", "out", "get", "got", "see", "let",
        "yes", "no", "ok", "okay", "yeah", "well", "like", "just", "also",
        "mark", "may", "june", "july", "april", "march", "august",
        "so", "to", "in", "on", "at", "it", "is", "be", "do", "go", "up",
        "good", "next", "last", "same", "some", "then", "than", "what",
        "when", "who", "how", "why", "very", "more", "most", "much", "many",
    }
)

_MIN_TOKEN_LEN = 3


@dataclass(frozen=True, slots=True)
class Participant:
    display_name: str
    tokens: tuple[str, ...]
    role: str | None = None
    speaker_line_count: int = 0
    first_seen: int = 0
    aliases: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class Mention:
    start: int
    end: int
    surface: str
    kind: MentionKind
    candidates: tuple[str, ...]
    confidence: float

    @property
    def ambiguous(self) -> bool:
        return len(self.candidates) > 1


_CONFIDENCE = {
    "speaker_label": 0.99,
    "full_name": 0.98,
    "alias": 0.95,
    "token": 0.90,
}
_AMBIGUOUS_TOKEN_CONFIDENCE = 0.85


class ParticipantRegistry:
    """Known participants plus a matcher for their mentions in the body."""

    __slots__ = ("_by_surface", "_labels", "_pattern", "participants")

    def __init__(
        self,
        participants: tuple[Participant, ...],
        labels: tuple[tuple[int, int, str], ...] = (),
    ) -> None:
        self.participants = participants
        self._labels = labels
        self._by_surface: dict[str, list[str]] = {}
        for p in participants:
            self._add_surface(p.display_name, p.display_name)
            for alias in p.aliases:
                self._add_surface(alias, p.display_name)
            for token in p.tokens:
                if len(token) >= _MIN_TOKEN_LEN and token.casefold() not in TOKEN_STOPWORDS:
                    self._add_surface(token, p.display_name)
        self._pattern = self._build_pattern()

    def _add_surface(self, surface: str, display_name: str) -> None:
        key = surface.casefold()
        owners = self._by_surface.setdefault(key, [])
        if display_name not in owners:
            owners.append(display_name)

    def _build_pattern(self) -> re.Pattern[str] | None:
        if not self._by_surface:
            return None
        # Longest first, so "Ahmed Farid" always wins over bare "Ahmed".
        surfaces = sorted(self._by_surface, key=len, reverse=True)
        alts = [re.escape(s).replace(r"\ ", r"\s+") for s in surfaces]
        return re.compile(r"(?<!\w)(?:" + "|".join(alts) + r")(?!\w)", re.IGNORECASE)

    # -- construction ----------------------------------------------------
    @classmethod
    def from_transcript(
        cls,
        parsed: ParsedTranscript,
        aliases: Mapping[str, str] | None = None,
    ) -> ParticipantRegistry:
        counts: dict[str, int] = {}
        first: dict[str, int] = {}
        for label in parsed.speaker_labels:
            counts[label.name] = counts.get(label.name, 0) + 1
            first.setdefault(label.name, label.name_start)

        roles = {d.name: d.role for d in parsed.declared_participants}
        for d in parsed.declared_participants:
            first.setdefault(d.name, d.start)

        alias_map: dict[str, set[str]] = {}
        for alias, target in (aliases or {}).items():
            alias_map.setdefault(target, set()).add(alias)

        names = sorted(set(counts) | set(roles), key=lambda n: first.get(n, 0))
        participants = tuple(
            Participant(
                display_name=name,
                tokens=tuple(name.split()),
                role=roles.get(name),
                speaker_line_count=counts.get(name, 0),
                first_seen=first.get(name, 0),
                aliases=frozenset(alias_map.get(name, set())),
            )
            for name in names
        )
        labels = tuple((label.name_start, label.name_end, label.name) for label in parsed.speaker_labels)
        return cls(participants, labels)

    # -- queries ---------------------------------------------------------
    def __len__(self) -> int:
        return len(self.participants)

    def lookup(self, surface: str) -> tuple[str, ...]:
        return tuple(self._by_surface.get(surface.casefold(), ()))

    def is_ambiguous(self, surface: str) -> bool:
        return len(self.lookup(surface)) > 1

    def mentions(self, text: str) -> Iterator[Mention]:
        """Yield every participant mention, structural labels first.

        Structural speaker labels are emitted from their recorded spans rather
        than searched for, so they are exact by construction.
        """
        label_spans = {(s, e) for s, e, _ in self._labels}
        for start, end, name in self._labels:
            yield Mention(
                start=start,
                end=end,
                surface=name,
                kind="speaker_label",
                candidates=(name,),
                confidence=_CONFIDENCE["speaker_label"],
            )
        if self._pattern is None:
            return
        for m in self._pattern.finditer(text):
            span = (m.start(), m.end())
            if span in label_spans:
                continue  # already emitted as a structural label
            surface = m.group()
            owners = self.lookup(re.sub(r"\s+", " ", surface))
            if not owners:
                continue
            is_full = any(surface.casefold() == o.casefold() for o in owners)
            if is_full:
                kind: MentionKind = "full_name"
            elif surface.casefold() in {
                a.casefold() for p in self.participants for a in p.aliases
            }:
                kind = "alias"
            else:
                kind = "token"
                # A bare token must look like a name: capitalised, and not an
                # ordinary word. Lower-case "ali" inside prose is not a person.
                if not surface[0].isupper():
                    continue
            confidence = _CONFIDENCE[kind]
            if kind == "token" and len(owners) > 1:
                confidence = _AMBIGUOUS_TOKEN_CONFIDENCE
            yield Mention(
                start=m.start(),
                end=m.end(),
                surface=surface,
                kind=kind,
                candidates=tuple(owners),
                confidence=confidence,
            )

    def to_safe_summary(self) -> dict[str, object]:
        """Counts only -- never the names themselves."""
        return {
            "participant_count": len(self.participants),
            "speaker_label_count": len(self._labels),
            "ambiguous_surfaces": sum(1 for v in self._by_surface.values() if len(v) > 1),
        }
