r"""Placeholder injection defence.

The attack: a user (or a document they supply) includes a literal
``<PERSON_001>`` in the input. A naive gateway passes it through untouched, the
model echoes it, and restoration expands it to whatever real person happened to
be assigned index 001 -- exfiltrating a value the attacker never supplied.

The defence is to treat the placeholder grammar as just another thing that must
be escaped. Any placeholder-shaped token in the *input* is detected before any
other entity as a ``LITERAL``, pseudonymized like anything else, and restores to
exactly the text the user typed.

That yields the invariant this module exists for:

    every <TYPE_NNN> token in the text sent to the model was minted by this
    gateway, in this conversation.

Detection runs *after* normalization, so HTML-entity-encoded and fullwidth
variants have already been folded into the plain form and are caught too.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from ..entities.entity import DetectedEntity, make_entity
from ..entities.taxonomy import EntityType

#: Any placeholder-shaped token, in any supported delimiter style, tolerating
#: internal zero-width characters that normalization may not have removed.
INJECTION_RE = re.compile(
    r"(?:<|⟦|\[\[)"
    r"[A-Z][A-Z0-9_​-‏]{1,31}"
    r"_\d{1,6}"
    r"(?:>|⟧|\]\])"
)


@dataclass(frozen=True, slots=True)
class InjectedPlaceholder:
    start: int
    end: int
    text: str

    def __repr__(self) -> str:
        return f"InjectedPlaceholder({self.start}:{self.end})"


class PlaceholderInjectionGuard:
    """Finds placeholder-shaped tokens in untrusted input."""

    def scan(self, text: str) -> tuple[InjectedPlaceholder, ...]:
        return tuple(
            InjectedPlaceholder(start=m.start(), end=m.end(), text=m.group())
            for m in INJECTION_RE.finditer(text)
        )

    def as_entities(
        self, text: str, found: Sequence[InjectedPlaceholder] | None = None
    ) -> tuple[DetectedEntity, ...]:
        """Emit each hit as a top-priority LITERAL entity.

        Priority 1000 puts these above every detector, so an injected token can
        never be overridden by a real detection, and they are assigned
        placeholders before anything else -- an attacker cannot race a
        later-allocated victim index.
        """
        hits = found if found is not None else self.scan(text)
        return tuple(
            make_entity(
                text_source=text,
                start=h.start,
                end=h.end,
                entity_type=EntityType.LITERAL,
                confidence=1.0,
                detector="injection_guard",
                source="placeholder_grammar",
                priority=1000,
                metadata={"injected": True},
            )
            for h in hits
        )
