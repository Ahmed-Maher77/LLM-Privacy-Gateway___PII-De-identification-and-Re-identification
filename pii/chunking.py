"""Split long documents into overlapping windows the NER model can actually read.

Transformer NER models cap out around 512 tokens. Feeding a 3,700-token
transcript straight in means everything past the cut is silently never
examined, so we window the text and map every offset back to the original.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Window:
    text: str
    offset: int


def iter_windows(
    text: str,
    max_chars: int = 1200,
    overlap_chars: int = 250,
) -> list[Window]:
    """Cut ``text`` into overlapping windows, preferring line boundaries.

    The overlap matters: an entity sitting on a window edge would be truncated
    in one window but appears whole in its neighbour, and the span resolver
    keeps the longer match.
    """
    if not text:
        return []
    if len(text) <= max_chars:
        return [Window(text=text, offset=0)]

    line_starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            line_starts.append(index + 1)

    windows: list[Window] = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        if end < len(text):
            end = _snap_backwards(text, line_starts, start, end)
        windows.append(Window(text=text[start:end], offset=start))
        if end >= len(text):
            break
        start = max(start + 1, end - overlap_chars)

    return windows


def _snap_backwards(text: str, line_starts: list[int], start: int, end: int) -> int:
    """Pull ``end`` back to the nearest line break, then word break."""
    candidates = [pos for pos in line_starts if start < pos <= end]
    if candidates:
        return candidates[-1]

    space = text.rfind(" ", start + 1, end)
    if space > start:
        return space + 1
    return end
