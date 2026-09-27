"""Layer 2: configurable domain rules.

This is where business knowledge lives -- the internal systems, customer names
and identifier formats that no general-purpose model can know about. It is
driven entirely by ``config/domain_lexicon.toml``, so a deployment extends its
coverage by editing data rather than by shipping code.

That separation matters for a privacy tool: hard-coding a handful of example
values into the detection logic produces something that demos well and protects
nothing in production.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..entities.entity import DetectedEntity, make_entity
from ..entities.taxonomy import EntityType
from ..errors import ConfigError
from .base import DEFAULT_PRIORITIES, DetectionContext

#: TOML section -> canonical entity type.
_SECTION_TYPES: Mapping[str, str] = {
    "internal_systems": EntityType.INTERNAL_SYSTEM,
    "internal_services": EntityType.INTERNAL_SERVICE,
    "customers": EntityType.CUSTOMER,
    "organizations": EntityType.ORGANIZATION,
    "projects": EntityType.PROJECT,
    "stakeholders": EntityType.STAKEHOLDER,
    "employees": EntityType.EMPLOYEE,
    "contracts": EntityType.CONTRACT,
    "internal_domains": EntityType.INTERNAL_URL,
}

DEFAULT_LEXICON_PATH = Path("config/domain_lexicon.toml")


@dataclass(frozen=True, slots=True)
class DomainLexicon:
    """Terms and patterns loaded from configuration."""

    terms: Mapping[str, tuple[tuple[str, float], ...]] = field(default_factory=dict)
    patterns: tuple[tuple[str, re.Pattern[str], float, str], ...] = ()

    @classmethod
    def load(cls, path: Path | str = DEFAULT_LEXICON_PATH) -> DomainLexicon:
        path = Path(path)
        if not path.exists():
            raise ConfigError(f"domain lexicon not found: {path}")
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"domain lexicon is not valid TOML: {path}") from exc
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DomainLexicon:
        terms: dict[str, list[tuple[str, float]]] = {}
        for section, entity_type in _SECTION_TYPES.items():
            block = data.get(section) or {}
            confidence = float(block.get("confidence", 0.85))
            if not 0.0 <= confidence <= 1.0:
                raise ConfigError(f"[{section}].confidence must lie in [0.0, 1.0]")
            for term in block.get("terms", ()):
                if not isinstance(term, str) or not term.strip():
                    raise ConfigError(f"[{section}].terms must contain non-empty strings")
                terms.setdefault(entity_type, []).append((term.strip(), confidence))

        patterns: list[tuple[str, re.Pattern[str], float, str]] = []
        for row in (data.get("patterns") or {}).get("rules", ()):
            if len(row) != 4:
                raise ConfigError("[patterns].rules entries must be [type, regex, confidence, id]")
            entity_type, expression, confidence, rule_id = row
            try:
                compiled = re.compile(expression)
            except re.error as exc:
                raise ConfigError(f"invalid domain pattern {rule_id!r}: {exc}") from exc
            patterns.append((str(entity_type), compiled, float(confidence), str(rule_id)))

        return cls(
            terms={k: tuple(v) for k, v in terms.items()},
            patterns=tuple(patterns),
        )

    def is_empty(self) -> bool:
        return not self.terms and not self.patterns


class DomainDetector:
    """Matches configured terms and patterns."""

    name = "domain"
    layer = 2

    def __init__(self, lexicon: DomainLexicon | None = None) -> None:
        self.lexicon = lexicon or DomainLexicon()
        self._priority = DEFAULT_PRIORITIES["domain"]
        self._term_pattern: re.Pattern[str] | None = None
        self._term_index: dict[str, tuple[str, float]] = {}
        self._compile_terms()

    def _compile_terms(self) -> None:
        surfaces: list[str] = []
        for entity_type, entries in self.lexicon.terms.items():
            for term, confidence in entries:
                key = term.casefold()
                # First section wins, so ordering in the file is meaningful.
                self._term_index.setdefault(key, (entity_type, confidence))
                surfaces.append(term)
        if not surfaces:
            self._term_pattern = None
            return
        # Longest first so "BrightPath Logistics" beats a bare "BrightPath".
        surfaces.sort(key=len, reverse=True)
        alts = [re.escape(s).replace(r"\ ", r"\s+") for s in surfaces]
        self._term_pattern = re.compile(
            r"(?<!\w)(?:" + "|".join(alts) + r")(?!\w)", re.IGNORECASE
        )

    def warmup(self) -> None:
        return None

    def detect(self, text: str, ctx: DetectionContext | None = None) -> tuple[DetectedEntity, ...]:
        out: list[DetectedEntity] = []

        if self._term_pattern is not None:
            for m in self._term_pattern.finditer(text):
                key = re.sub(r"\s+", " ", m.group()).casefold()
                found = self._term_index.get(key)
                if found is None:
                    continue
                entity_type, confidence = found
                out.append(
                    make_entity(
                        text_source=text,
                        start=m.start(),
                        end=m.end(),
                        entity_type=entity_type,
                        confidence=confidence,
                        detector=self.name,
                        source="lexicon",
                        priority=self._priority,
                        reported_text=m.group(),
                    )
                )

        for entity_type, compiled, confidence, rule_id in self.lexicon.patterns:
            for m in compiled.finditer(text):
                out.append(
                    make_entity(
                        text_source=text,
                        start=m.start(),
                        end=m.end(),
                        entity_type=entity_type,
                        confidence=confidence,
                        detector=self.name,
                        source=rule_id,
                        priority=self._priority,
                        reported_text=m.group(),
                    )
                )
        return tuple(out)


def build(config: Any = None, lexicon: DomainLexicon | None = None, **_: Any) -> DomainDetector:
    if lexicon is not None:
        return DomainDetector(lexicon)
    path = getattr(config, "domain_lexicon_path", DEFAULT_LEXICON_PATH)
    try:
        return DomainDetector(DomainLexicon.load(path))
    except ConfigError:
        # An absent lexicon is a legitimate deployment state (no domain terms
        # configured yet); an unreadable one is not, and load() raised already.
        if Path(path).exists():
            raise
        return DomainDetector(DomainLexicon())


def build_terms_only(terms: Mapping[str, Sequence[str]], confidence: float = 0.9) -> DomainDetector:
    """Convenience constructor for tests."""
    return DomainDetector(
        DomainLexicon(terms={k: tuple((t, confidence) for t in v) for k, v in terms.items()})
    )
