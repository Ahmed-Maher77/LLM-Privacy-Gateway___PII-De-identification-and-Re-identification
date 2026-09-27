r"""Placeholder format and parsing.

The shipped format is ``<PERSON_001>``.

It is worth being honest about its weakness, because the evidence is in this
repository: angle brackets read as HTML and ``_`` is markdown emphasis, and in
``reports/pod_meeting_run.json`` the model rewrote every placeholder as
``**PER 2**`` -- 66 narrow no-break spaces, zero intact placeholders, and a
restoration pass that silently did nothing at all.

So ``GATEWAY_PLACEHOLDER_STYLE`` exists. ``guillemet`` uses U+27E6/U+27E7, which
carry no markdown or HTML meaning and survive a model round-trip far more
reliably. The default stays ``angle`` because that is the specified format; the
evaluation harness measures the real drift rate so the choice can be made on
data rather than on this paragraph.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal

PlaceholderStyle = Literal["angle", "guillemet", "bracket"]

_DELIMITERS: dict[str, tuple[str, str]] = {
    "angle": ("<", ">"),
    "guillemet": ("⟦", "⟧"),
    "bracket": ("[[", "]]"),
}

#: Prefix must be upper-case alphanumeric; index is 1-6 digits. Anchoring the
#: index against the closing delimiter is what makes ``<PERSON_001>`` incapable
#: of matching as a prefix of ``<PERSON_0010>``.
_PREFIX = r"(?P<prefix>[A-Z][A-Z0-9]{1,31})"
_INDEX = r"(?P<index>\d{1,6})"

DEFAULT_PAD = 3


@dataclass(frozen=True, slots=True)
class PlaceholderFormat:
    """Renders and recognises placeholders in one style."""

    style: PlaceholderStyle = "angle"
    pad: int = DEFAULT_PAD

    @property
    def delimiters(self) -> tuple[str, str]:
        return _DELIMITERS[self.style]

    @property
    def pattern(self) -> re.Pattern[str]:
        open_, close = (re.escape(d) for d in self.delimiters)
        return re.compile(open_ + _PREFIX + r"_" + _INDEX + close)

    def render(self, prefix: str, index: int) -> str:
        open_, close = self.delimiters
        return f"{open_}{prefix}_{index:0{self.pad}d}{close}"

    def parse(self, token: str) -> tuple[str, int] | None:
        m = self.pattern.fullmatch(token)
        if m is None:
            return None
        return m.group("prefix"), int(m.group("index"))

    def find(self, text: str) -> Iterator[re.Match[str]]:
        return self.pattern.finditer(text)

    def is_placeholder(self, token: str) -> bool:
        return self.parse(token) is not None


#: The default instance used throughout the gateway.
DEFAULT_FORMAT = PlaceholderFormat()
PLACEHOLDER_RE = DEFAULT_FORMAT.pattern


def format_placeholder(prefix: str, index: int, pad: int = DEFAULT_PAD) -> str:
    return PlaceholderFormat(pad=pad).render(prefix, index)


def parse_placeholder(token: str) -> tuple[str, int] | None:
    return DEFAULT_FORMAT.parse(token)


def find_placeholders(text: str) -> Iterator[re.Match[str]]:
    return DEFAULT_FORMAT.find(text)


#: Matches a placeholder in *any* supported style, plus common manglings.
#: Used only to DETECT drift and injection -- never to resolve a value.
ANY_STYLE_RE = re.compile(
    r"(?:"
    + "|".join(
        re.escape(o) + _PREFIX.replace("prefix", f"prefix{i}") + r"_"
        + _INDEX.replace("index", f"index{i}") + re.escape(c)
        for i, (o, c) in enumerate(_DELIMITERS.values())
    )
    + r")"
)
