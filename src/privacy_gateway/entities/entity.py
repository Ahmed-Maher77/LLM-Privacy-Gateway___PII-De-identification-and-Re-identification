"""The single internal representation every detector must produce.

Two properties of this module carry most of the safety weight:

1. ``DetectedEntity.text`` is *always* re-read from the source text by
   :func:`make_entity`. A detector's own idea of what it matched (Hugging
   Face's ``word``, Qwen's echoed string) is recorded only as a diagnostic.
   The prototype trusted ``entity["word"]`` and used it as a ``str.replace``
   key, which is how a sub-word fragment ``"N"`` came to be replaced
   document-wide, producing ``<PER_2>ania Fahmy``.

2. ``__repr__`` never contains the matched text. The realistic leak vector is
   not a deliberate ``print(entity.text)`` -- it is ``logger.debug(f"got
   {entity}")`` written in a hurry. Overriding the repr makes that line safe by
   construction.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any

#: Per-process salt. Hashes correlate *within* one run (so a leak finding can be
#: tied to a mapping entry) but are not a stable identifier across runs, which
#: would make logs a rainbow-table target.
_PROCESS_SALT = secrets.token_hex(16)


def _fingerprint(value: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}\x1f{value}".encode()).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class DetectedEntity:
    """One candidate span of sensitive data, in canonical-text coordinates."""

    entity_type: str
    text: str
    start: int
    end: int
    confidence: float
    detector: str
    source: str = ""
    priority: int = 0
    # Diagnostic provenance, deliberately excluded from equality and hashing:
    # two entities are the same entity when their type, span, confidence and
    # detector agree, regardless of what notes a stage attached along the way.
    metadata: Mapping[str, Any] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        if not self.entity_type or not self.entity_type.isupper():
            raise ValueError("entity_type must be a non-empty upper-case label")
        if self.start < 0:
            raise ValueError("start must be non-negative")
        if self.end <= self.start:
            raise ValueError("end must be greater than start")
        # Checkable without the source text, and catches the majority of
        # detector offset bugs for free.
        if self.end - self.start != len(self.text):
            raise ValueError("span length does not match text length")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must lie in [0.0, 1.0]")
        if not self.detector:
            raise ValueError("detector must be set")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    # -- derived ---------------------------------------------------------
    @property
    def span(self) -> tuple[int, int]:
        return (self.start, self.end)

    @property
    def length(self) -> int:
        return self.end - self.start

    # -- transformations (always return a new instance) -------------------
    def shifted(self, delta: int) -> DetectedEntity:
        """Rebase into another coordinate space, e.g. chunk -> whole document."""
        return replace(self, start=self.start + delta, end=self.end + delta)

    def with_span(self, start: int, end: int, text: str) -> DetectedEntity:
        return replace(self, start=start, end=end, text=text)

    def with_metadata(self, **kv: Any) -> DetectedEntity:
        return replace(self, metadata={**dict(self.metadata), **kv})

    def with_confidence(self, confidence: float) -> DetectedEntity:
        return replace(self, confidence=confidence)

    def fingerprint(self, salt: str = _PROCESS_SALT) -> str:
        return _fingerprint(f"{self.entity_type}\x1f{self.text}", salt)

    # -- safety ----------------------------------------------------------
    def __repr__(self) -> str:
        return (
            f"DetectedEntity({self.entity_type} {self.start}:{self.end} "
            f"det={self.detector} conf={self.confidence:.2f} "
            f"sha={self.fingerprint()})"
        )

    __str__ = __repr__


def make_entity(
    *,
    text_source: str,
    start: int,
    end: int,
    entity_type: str,
    confidence: float,
    detector: str,
    source: str = "",
    priority: int = 0,
    metadata: Mapping[str, Any] | None = None,
    reported_text: str | None = None,
) -> DetectedEntity:
    """Build an entity whose ``text`` is read from ``text_source``.

    This is the *only* sanctioned way to construct a :class:`DetectedEntity`
    from detector output. ``reported_text`` -- what the detector claimed it
    matched -- is compared against the real slice and recorded as a diagnostic
    flag, but is never used as the entity's text.
    """
    if start < 0 or end > len(text_source):
        raise ValueError("span lies outside the source text")
    slice_ = text_source[start:end]
    meta = dict(metadata or {})
    if reported_text is not None and reported_text != slice_:
        meta["reported_text_mismatch"] = True
        meta["reported_len"] = len(reported_text)
    return DetectedEntity(
        entity_type=entity_type,
        text=slice_,
        start=start,
        end=end,
        confidence=confidence,
        detector=detector,
        source=source,
        priority=priority,
        metadata=meta,
    )
