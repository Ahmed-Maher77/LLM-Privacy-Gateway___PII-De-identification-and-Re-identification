r"""Monotone offset mapping between normalized and raw text.

Normalization genuinely changes length: ``\r\n`` becomes ``\n`` (one character
deleted), ``&amp;`` becomes ``&`` (four deleted), NFC composition merges a base
character and a combining mark. A length-preserving fake would have to pad the
middle of words, which breaks the tokenizer, the email pattern's lookahead and
word-boundary validation -- exactly the invariants the gateway exists to uphold.

So we normalize for real, treat the normalized text as canonical, and keep a
sparse map back to raw offsets for audit and reporting. An anchor is stored only
where the delta changes, so a 1 MB document with a few thousand edits costs a
few thousand integers rather than a million.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

EditKind = Literal["copy", "subst", "delete", "expand"]


@dataclass(frozen=True, slots=True)
class Edit:
    """One contiguous transformation applied during normalization."""

    orig_start: int
    orig_end: int
    new_start: int
    new_end: int
    kind: EditKind

    @property
    def is_one_to_one(self) -> bool:
        return (self.orig_end - self.orig_start) == (self.new_end - self.new_start)


class OffsetMap:
    """Maps an index in the normalized text to an index in the original text.

    The map is monotone non-decreasing. Where a span endpoint falls inside a
    region that is not 1:1 it is snapped outwards -- start snaps down, end snaps
    up -- so spans only ever widen. Widening is the conservative direction: an
    audit span one character too long is harmless, one too short hides part of
    what was matched.
    """

    __slots__ = ("_edits", "_new", "_new_len", "_orig", "_orig_len")

    def __init__(self, edits: Sequence[Edit], orig_len: int, new_len: int) -> None:
        self._orig_len = orig_len
        self._new_len = new_len
        self._edits = tuple(
            sorted(
                (e for e in edits if not (e.kind == "copy" and e.is_one_to_one)),
                key=lambda e: e.new_start,
            )
        )
        # Anchor pairs at every edit boundary. Between anchors the map is a
        # constant shift, so a bisect plus one addition answers any query.
        new_anchors: list[int] = [0]
        orig_anchors: list[int] = [0]
        for e in self._edits:
            if new_anchors[-1] != e.new_start:
                new_anchors.append(e.new_start)
                orig_anchors.append(e.orig_start)
            else:
                orig_anchors[-1] = e.orig_start
            new_anchors.append(e.new_end)
            orig_anchors.append(e.orig_end)
        self._new = new_anchors
        self._orig = orig_anchors

    def __len__(self) -> int:
        return self._new_len

    # -- queries ---------------------------------------------------------
    def to_original_index(self, i: int, *, side: Literal["left", "right"] = "left") -> int:
        """Map one normalized index back to an original index."""
        if i < 0:
            raise ValueError("index must be non-negative")
        if i >= self._new_len:
            return self._orig_len
        for e in self._edits:
            if e.new_start <= i < e.new_end:
                return e.orig_start if side == "left" else e.orig_end
        k = bisect_right(self._new, i) - 1
        return self._orig[k] + (i - self._new[k])

    def _exclusive_end(self, end: int) -> int:
        """Map an exclusive end index. Snaps up when it lands inside an edit."""
        if end >= self._new_len:
            return self._orig_len
        for e in self._edits:
            if e.new_start < end < e.new_end:
                return e.orig_end
        k = bisect_right(self._new, end) - 1
        return self._orig[k] + (end - self._new[k])

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        """Map a normalized span to the original span that produced it."""
        if end < start:
            raise ValueError("end must not precede start")
        o_start = self.to_original_index(start, side="left")
        if end == start:
            return o_start, o_start
        o_end = max(self._exclusive_end(end), o_start)
        return o_start, min(o_end, self._orig_len)

    def is_exact(self, start: int, end: int) -> bool:
        """False when the span touches a region that is not 1:1."""
        return not any(
            e.new_start < end and start < e.new_end
            for e in self._edits
            if not e.is_one_to_one
        )


def merge_edits(edits: Sequence[Edit]) -> list[Edit]:
    """Sort, drop empties and coalesce overlapping edits."""
    out: list[Edit] = []
    for e in sorted(edits, key=lambda x: (x.new_start, x.new_end)):
        if e.new_end < e.new_start or e.orig_end < e.orig_start:
            continue
        if out and e.new_start < out[-1].new_end:
            prev = out[-1]
            out[-1] = Edit(
                orig_start=min(prev.orig_start, e.orig_start),
                orig_end=max(prev.orig_end, e.orig_end),
                new_start=min(prev.new_start, e.new_start),
                new_end=max(prev.new_end, e.new_end),
                kind="subst",
            )
        else:
            out.append(e)
    return out


class EditRecorder:
    """Accumulates edits while a normalization pass rewrites a string.

    A pass walks the source left to right, calling :meth:`copy` for untouched
    runs and :meth:`replace` for transformed ones, then :meth:`finish`.
    """

    __slots__ = ("_new", "_orig", "edits", "parts")

    def __init__(self) -> None:
        self.parts: list[str] = []
        self.edits: list[Edit] = []
        self._orig = 0
        self._new = 0

    @property
    def orig_pos(self) -> int:
        return self._orig

    def copy(self, text: str, upto: int) -> None:
        """Copy source text unchanged up to ``upto``."""
        if upto <= self._orig:
            return
        chunk = text[self._orig : upto]
        self.parts.append(chunk)
        self._new += len(chunk)
        self._orig = upto

    def replace(self, orig_end: int, replacement: str) -> None:
        """Consume source up to ``orig_end`` and emit ``replacement`` instead."""
        o_start, n_start = self._orig, self._new
        self.parts.append(replacement)
        self._new += len(replacement)
        self._orig = orig_end
        consumed = orig_end - o_start
        produced = len(replacement)
        if produced == 0:
            kind: EditKind = "delete"
        elif consumed >= produced:
            kind = "subst"
        else:
            kind = "expand"
        self.edits.append(
            Edit(
                orig_start=o_start,
                orig_end=orig_end,
                new_start=n_start,
                new_end=self._new,
                kind=kind,
            )
        )

    def finish(self, text: str) -> tuple[str, OffsetMap]:
        self.copy(text, len(text))
        out = "".join(self.parts)
        return out, OffsetMap(merge_edits(self.edits), len(text), len(out))
