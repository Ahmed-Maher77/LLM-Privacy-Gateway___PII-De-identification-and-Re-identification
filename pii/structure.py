"""Keep JSON and code blocks syntactically intact while redacting inside them.

A redaction that turns ``"mac_address": "00:1B:44:11:3A:B7"`` into something
that no longer parses has destroyed the log the reader needed. The goal is the
opposite: mask the *value*, leave every quote, colon and brace alone, and never
touch the key.

Structure is found by **brace balance, not by fences**. The JSON block in a
real meeting transcript is introduced by a bare line reading ``JSON`` with no
backticks anywhere, so a fence-based detector finds nothing at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from collections.abc import Sequence

from .spans import Span

# Characters that carry structural meaning inside a JSON or code region.
DELIMITERS = frozenset("\"'`:,{}[]\n")

# Types that are never worth masking inside a key position. A key is a schema
# name, not somebody's data.
STRUCTURE_SAFE_TYPES = frozenset({"ORG", "LOCATION", "JOB_TITLE", "MEETING_TITLE"})

# Sources whose spans may be trimmed. Pattern spans are exempt because the
# values they match legitimately contain delimiters: a MAC address is five
# colons, a URL has colons and slashes, an email has dots. Clipping those
# would shred the very secrets we are here to remove.
CLIPPABLE_SOURCES = frozenset({"model", "sweep", "roster", "lexicon"})

_KEY_RE = re.compile(r"(\"[^\"\n]{1,120}\"|'[^'\n]{1,120}')\s*:")
_FENCE_RE = re.compile(r"^[ \t]*```[^\n]*\n(.*?)^[ \t]*```", re.MULTILINE | re.DOTALL)


@dataclass(frozen=True, slots=True)
class Region:
    start: int
    end: int
    kind: str  # "json" | "fenced"


@dataclass(frozen=True, slots=True)
class StructureMap:
    regions: tuple[Region, ...] = ()
    key_zones: tuple[tuple[int, int], ...] = ()

    def region_at(self, index: int) -> Region | None:
        for region in self.regions:
            if region.start <= index < region.end:
                return region
        return None

    def in_key_zone(self, start: int, end: int) -> bool:
        return any(start < zone_end and zone_start < end for zone_start, zone_end in self.key_zones)

    def summary(self) -> dict:
        return {
            "regions": len(self.regions),
            "key_zones": len(self.key_zones),
            "kinds": sorted({region.kind for region in self.regions}),
        }


def find_json_regions(text: str) -> list[Region]:
    """Brace-balance scan from any line-initial ``{`` or ``[``.

    Tracks string state and backslash escapes so a brace inside a quoted value
    does not confuse the depth count. A region is accepted only if it closes
    and contains at least one ``"key":`` pair, which keeps ordinary prose
    containing a stray brace from being treated as structure.
    """
    regions: list[Region] = []
    index = 0
    length = len(text)

    while index < length:
        char = text[index]
        at_line_start = index == 0 or text[index - 1] == "\n"
        if char not in "{[" or not at_line_start:
            index += 1
            continue

        depth = 0
        in_string = False
        quote = ""
        escaped = False
        cursor = index

        while cursor < length:
            current = text[cursor]
            if in_string:
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    in_string = False
            elif current in "\"'":
                in_string = True
                quote = current
            elif current in "{[":
                depth += 1
            elif current in "}]":
                depth -= 1
                if depth == 0:
                    break
            cursor += 1

        if depth == 0 and cursor < length:
            block = text[index : cursor + 1]
            if _KEY_RE.search(block):
                regions.append(Region(start=index, end=cursor + 1, kind="json"))
                index = cursor + 1
                continue
        index += 1

    return regions


def find_fenced_regions(text: str) -> list[Region]:
    """Triple-backtick code blocks, when the document happens to use them."""
    return [
        Region(start=match.start(), end=match.end(), kind="fenced")
        for match in _FENCE_RE.finditer(text)
    ]


def find_key_zones(text: str, regions: Sequence[Region]) -> list[tuple[int, int]]:
    """Character ranges of every quoted key immediately preceding a colon."""
    zones: list[tuple[int, int]] = []
    for region in regions:
        block = text[region.start : region.end]
        for match in _KEY_RE.finditer(block):
            zones.append((region.start + match.start(1), region.start + match.end(1)))
    return zones


def find_gutter_zones(text: str) -> list[tuple[int, int]]:
    """Identify left-gutter line numbers in deposition/arbitration transcripts."""
    zones: list[tuple[int, int]] = []
    pattern = re.compile(r"^[ \t]*(\d{1,4})(?=[ \t]{2,})", re.MULTILINE)
    matches = list(pattern.finditer(text))
    if len(matches) < 3:
        return []

    gutter_matches: list[re.Match[str]] = []
    for i in range(len(matches)):
        m = matches[i]
        val = int(m.group(1))
        is_seq = False
        if i > 0 and int(matches[i - 1].group(1)) + 1 == val:
            is_seq = True
        elif i + 1 < len(matches) and val + 1 == int(matches[i + 1].group(1)):
            is_seq = True
        elif val == 1:
            is_seq = True
        if is_seq:
            gutter_matches.append(m)

    for m in gutter_matches:
        zones.append((m.start(1), m.end(1)))
    return zones


def analyze_structure(text: str) -> StructureMap:
    regions = find_json_regions(text) + find_fenced_regions(text)
    regions.sort(key=lambda region: region.start)
    key_zones = find_key_zones(text, regions) + find_gutter_zones(text)
    return StructureMap(
        regions=tuple(regions),
        key_zones=tuple(key_zones),
    )


def segment_bounds(text: str, start: int, end: int, region: Region) -> tuple[int, int]:
    """Widest delimiter-free range around ``start:end`` inside ``region``."""
    left = start
    while left > region.start and text[left - 1] not in DELIMITERS:
        left -= 1
    right = end
    while right < region.end and text[right] not in DELIMITERS:
        right += 1
    return left, right


def _trimmed(text: str, start: int, end: int) -> tuple[int, int]:
    """Drop leading and trailing non-alphanumerics, as the detectors do."""
    while start < end and not text[start].isalnum():
        start += 1
    while end > start and not text[end - 1].isalnum():
        end -= 1
    return start, end


def clip_span(text: str, span: Span, structure: StructureMap) -> Span | None:
    """Trim a span so it cannot break the structure it sits in.

    Returns the span untouched when it is in ordinary prose. That exemption is
    essential: prose is full of commas, and a global "no span may cross a
    comma" rule would forbid ``742 Evergreen Terrace, Springfield, OR 97477``
    from ever being matched as one address.
    """
    if span.source not in CLIPPABLE_SOURCES:
        return span

    region = structure.region_at(span.start)
    if region is None:
        return span

    left, right = segment_bounds(text, span.start, span.end, region)
    start = max(span.start, left)
    end = min(span.end, right)
    start, end = _trimmed(text, start, end)
    if end <= start:
        return None
    if (start, end) == (span.start, span.end):
        return span

    return Span(
        start=start,
        end=end,
        label=span.label,
        text=text[start:end],
        score=span.score,
        source=span.source,
        identity=span.identity,
    )


def protect_spans(
    text: str,
    spans: Sequence[Span],
    structure: StructureMap,
    *,
    structure_safe_types: frozenset[str] = STRUCTURE_SAFE_TYPES,
) -> list[Span]:
    """Clip spans to their structural cell and keep schema keys readable.

    A key is dropped for the types in ``structure_safe_types`` -- masking
    ``"mac_address"`` the key helps nobody. Other types are clipped rather
    than dropped, because a key literally named ``"sarah_jenkins"`` is real
    data, and a blanket "keys are never redacted" rule would hand an attacker
    a free exfiltration channel: put the secret in a key.
    """
    if not structure.regions:
        return list(spans)

    kept: list[Span] = []
    for span in spans:
        if structure.in_key_zone(span.start, span.end) and span.label in structure_safe_types:
            continue
        clipped = clip_span(text, span, structure)
        if clipped is not None:
            kept.append(clipped)
    return kept
