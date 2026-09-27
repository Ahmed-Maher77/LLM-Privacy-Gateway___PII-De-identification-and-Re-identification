"""Layer 0/2: participant mentions as entities.

Highest priority in the ladder, because a speaker label is a fact about the
document's structure rather than a model's guess. In a noisy ASR transcript
this is what guarantees the participants are protected even when every
statistical layer mangles their names.

Ambiguous mentions are emitted with their candidate list attached and a lower
confidence. They are protected, never attributed.
"""

from __future__ import annotations

from typing import Any

from ..entities.entity import DetectedEntity, make_entity
from ..entities.taxonomy import EntityType
from ..preprocessing.registry import ParticipantRegistry
from .base import DEFAULT_PRIORITIES, DetectionContext


class RegistryDetector:
    """Turns :class:`ParticipantRegistry` mentions into entities."""

    name = "registry"
    layer = 2

    def __init__(self, registry: ParticipantRegistry | None = None) -> None:
        self.registry = registry
        self._priority = DEFAULT_PRIORITIES["registry"]

    def warmup(self) -> None:
        return None

    def detect(self, text: str, ctx: DetectionContext | None = None) -> tuple[DetectedEntity, ...]:
        if self.registry is None or not self.registry.participants:
            return ()
        out: list[DetectedEntity] = []
        for mention in self.registry.mentions(text):
            out.append(
                make_entity(
                    text_source=text,
                    start=mention.start,
                    end=mention.end,
                    entity_type=EntityType.PERSON,
                    confidence=mention.confidence,
                    detector=self.name,
                    source=mention.kind,
                    priority=self._priority,
                    metadata={
                        "registry_kind": mention.kind,
                        "ambiguous": mention.ambiguous,
                        # Recorded so a reviewer can see that e.g. a bare
                        # "Ahmed" could be any of three participants -- the
                        # gateway reports the ambiguity instead of guessing.
                        "candidates": mention.candidates,
                        "candidate_count": len(mention.candidates),
                    },
                    reported_text=mention.surface,
                )
            )
        return tuple(out)


def build(config: Any = None, registry: ParticipantRegistry | None = None, **_: Any) -> RegistryDetector:
    return RegistryDetector(registry)
