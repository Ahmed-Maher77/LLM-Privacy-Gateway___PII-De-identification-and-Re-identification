"""Layer 1: deterministic pattern detection.

Pure ``re`` over a ``str``. No model, no network, no state. This layer is the
safety floor: if it raises, that is a code defect rather than an environmental
one, so it aborts in both fail modes.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from ..entities.entity import DetectedEntity, make_entity
from .base import DEFAULT_PRIORITIES, DetectionContext
from .patterns import DETERMINISTIC_RULES


class RegexDetector:
    """Structured identifiers with deterministic, high-confidence patterns."""

    name = "regex"

    def __init__(self, rules: Sequence[tuple[str, object, float, str]] | None = None) -> None:
        self._rules = tuple(rules if rules is not None else DETERMINISTIC_RULES)
        self._priority = DEFAULT_PRIORITIES["regex"]

    def warmup(self) -> None:  # nothing to load
        return None

    def detect(self, text: str, ctx: DetectionContext | None = None) -> tuple[DetectedEntity, ...]:
        out: list[DetectedEntity] = []
        for entity_type, matcher, confidence, rule_id in self._rules:
            matches = (
                matcher.finditer(text)
                if isinstance(matcher, re.Pattern)
                else matcher(text)  # type: ignore[operator]
            )
            for m in matches:
                # A pattern anchored to a label ("password: hunter2")
                # matches the label too, but only the value itself is the
                # entity; a named "value" group narrows the span to just that.
                if "value" in m.re.groupindex:
                    start, end, matched = m.start("value"), m.end("value"), m.group("value")
                else:
                    start, end, matched = m.start(), m.end(), m.group()
                out.append(
                    make_entity(
                        text_source=text,
                        start=start,
                        end=end,
                        entity_type=entity_type,
                        confidence=confidence,
                        detector=self.name,
                        source=rule_id,
                        priority=self._priority,
                        reported_text=matched,
                    )
                )
        return tuple(out)


def build(config: Any = None, **_: Any) -> RegexDetector:
    return RegexDetector()
