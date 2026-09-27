"""Conversation-scoped placeholder mapping.

The mapping is the secret. It never reaches the model, the prompt, a log, a
trace or a report by default. A ``MappingStore`` instance is the only thing that
can turn ``<PERSON_001>`` back into a name, and it is scoped to exactly one
conversation -- there is deliberately no process-wide placeholder registry and no
API for enumerating across conversations.

Identity: two mentions are the same entity when their type and normalised
surface form agree. Normalisation collapses whitespace, strips wrappers and a
possessive, and case-folds unless the type is case-sensitive.

Case-folding has a cost worth naming: ``canonical`` is the first-seen spelling,
so a later ``"ahmed farid"`` restores as ``"Ahmed Farid"``. That is accepted
because case-sensitive identity would fragment one person across three or four
placeholders in chaotic ASR casing, which is worse for both privacy and
summary quality. Every divergent spelling is recorded in ``occurrences`` and
surfaced in the report as ``case_variants``.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

from ..entities.entity import DetectedEntity
from ..errors import ConversationMismatchError, PlaceholderCollisionError
from ..policy.actions import EntityRule
from .placeholders import DEFAULT_FORMAT, PlaceholderFormat

_WS_RE = re.compile(r"\s+")
_POSSESSIVE_RE = re.compile(r"['’]s$")
_WRAPPERS = " \t\r\n`\"'*_"


def identity_key(entity_type: str, text: str, *, case_sensitive: bool) -> str:
    """The key under which two mentions count as the same entity."""
    value = unicodedata.normalize("NFKC", text)
    value = _WS_RE.sub(" ", value).strip()
    value = value.strip(_WRAPPERS)
    value = _POSSESSIVE_RE.sub("", value)
    if not case_sensitive:
        value = value.casefold()
    return f"{entity_type}\x1f{value}"


@dataclass(frozen=True, slots=True)
class Occurrence:
    start: int
    end: int
    exact_text: str
    detector: str
    confidence: float

    def __repr__(self) -> str:  # never include exact_text
        return f"Occurrence({self.start}:{self.end} det={self.detector})"


@dataclass(frozen=True, slots=True)
class MappingEntry:
    placeholder: str
    entity_type: str
    placeholder_prefix: str
    canonical: str
    identity_key: str
    case_sensitive: bool = False
    occurrences: tuple[Occurrence, ...] = ()
    detectors: frozenset[str] = field(default_factory=frozenset)
    max_confidence: float = 0.0
    alias_candidates: tuple[str, ...] = ()

    @property
    def variants(self) -> frozenset[str]:
        return frozenset(o.exact_text for o in self.occurrences)

    @property
    def has_case_variants(self) -> bool:
        return len({v.casefold() for v in self.variants}) < len(self.variants) or len(
            self.variants
        ) > 1

    def __repr__(self) -> str:  # never include canonical
        return (
            f"MappingEntry({self.placeholder} type={self.entity_type} "
            f"occurrences={len(self.occurrences)})"
        )


class MappingStore:
    """Placeholder <-> value mapping for one conversation."""

    __slots__ = ("_by_identity", "_by_placeholder", "_counters", "conversation_id", "created_at", "format")

    def __init__(
        self,
        conversation_id: str,
        placeholder_format: PlaceholderFormat = DEFAULT_FORMAT,
    ) -> None:
        if not conversation_id:
            raise ValueError("conversation_id is required")
        self.conversation_id = conversation_id
        self.created_at = datetime.now(UTC)
        self.format = placeholder_format
        self._by_identity: dict[str, MappingEntry] = {}
        self._by_placeholder: dict[str, MappingEntry] = {}
        self._counters: dict[str, int] = {}

    # -- assignment --------------------------------------------------------
    def assign(self, entity: DetectedEntity, rule: EntityRule) -> str:
        """Return the placeholder for ``entity``, minting one if it is new."""
        key = identity_key(entity.entity_type, entity.text, case_sensitive=rule.case_sensitive)
        existing = self._by_identity.get(key)
        if existing is not None:
            self._record(existing, entity)
            return existing.placeholder

        prefix = rule.placeholder_prefix
        index = self._counters[prefix] = self._counters.get(prefix, 0) + 1
        placeholder = self.format.render(prefix, index)
        if placeholder in self._by_placeholder:  # cannot happen; assert it anyway
            raise PlaceholderCollisionError(f"placeholder {placeholder} already assigned")

        entry = MappingEntry(
            placeholder=placeholder,
            entity_type=entity.entity_type,
            placeholder_prefix=prefix,
            canonical=entity.text,
            identity_key=key,
            case_sensitive=rule.case_sensitive,
            occurrences=(
                Occurrence(entity.start, entity.end, entity.text, entity.detector, entity.confidence),
            ),
            detectors=frozenset({entity.detector}),
            max_confidence=entity.confidence,
            alias_candidates=tuple(entity.metadata.get("candidates", ()) or ()),
        )
        self._by_identity[key] = entry
        self._by_placeholder[placeholder] = entry
        return placeholder

    def _record(self, entry: MappingEntry, entity: DetectedEntity) -> None:
        updated = replace(
            entry,
            occurrences=(
                *entry.occurrences,
                Occurrence(
                    entity.start, entity.end, entity.text, entity.detector, entity.confidence
                ),
            ),
            detectors=entry.detectors | {entity.detector},
            max_confidence=max(entry.max_confidence, entity.confidence),
        )
        self._by_identity[entry.identity_key] = updated
        self._by_placeholder[entry.placeholder] = updated

    # -- lookup ------------------------------------------------------------
    def get(self, placeholder: str) -> MappingEntry | None:
        return self._by_placeholder.get(placeholder)

    def __contains__(self, placeholder: object) -> bool:
        return placeholder in self._by_placeholder

    def __len__(self) -> int:
        return len(self._by_placeholder)

    def __iter__(self) -> Iterator[MappingEntry]:
        return iter(self._by_placeholder.values())

    def placeholders(self) -> frozenset[str]:
        return frozenset(self._by_placeholder)

    def entries(self) -> tuple[MappingEntry, ...]:
        return tuple(self._by_placeholder.values())

    def require_conversation(self, conversation_id: str) -> None:
        """Guard against using a mapping from another conversation."""
        if conversation_id != self.conversation_id:
            raise ConversationMismatchError()

    def sensitive_values(self) -> tuple[tuple[str, MappingEntry], ...]:
        """Every value that must not appear in text leaving the gateway."""
        out: list[tuple[str, MappingEntry]] = []
        for entry in self._by_placeholder.values():
            seen: set[str] = set()
            for value in (entry.canonical, *entry.variants):
                if value and value not in seen:
                    seen.add(value)
                    out.append((value, entry))
        return tuple(out)

    # -- serialisation -----------------------------------------------------
    def to_dict(self, *, include_values: bool) -> dict[str, object]:
        """Serialise. ``include_values=False`` is safe to write to a report."""
        entries = []
        for entry in self._by_placeholder.values():
            row: dict[str, object] = {
                "placeholder": entry.placeholder,
                "entity_type": entry.entity_type,
                "occurrences": len(entry.occurrences),
                "detectors": sorted(entry.detectors),
                "max_confidence": round(entry.max_confidence, 4),
                "ambiguous_candidates": len(entry.alias_candidates),
            }
            if include_values:
                row["canonical"] = entry.canonical
                row["variants"] = sorted(entry.variants)
                row["spans"] = [[o.start, o.end] for o in entry.occurrences]
            entries.append(row)
        return {
            "conversation_id": self.conversation_id,
            "created_at": self.created_at.isoformat(),
            "style": self.format.style,
            "pad": self.format.pad,
            "contains_values": include_values,
            "entries": entries,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> MappingStore:
        if not data.get("contains_values"):
            raise ValueError("cannot rebuild a mapping from a redacted serialisation")
        store = cls(
            str(data["conversation_id"]),
            PlaceholderFormat(
                style=str(data.get("style", "angle")),  # type: ignore[arg-type]
                pad=int(data.get("pad", 3)),
            ),
        )
        for row in data["entries"]:  # type: ignore[index]
            spans = row.get("spans") or [[0, len(str(row["canonical"]))]]
            entry = MappingEntry(
                placeholder=str(row["placeholder"]),
                entity_type=str(row["entity_type"]),
                placeholder_prefix=str(row["placeholder"]).strip("<>[]⟦⟧").rsplit("_", 1)[0],
                canonical=str(row["canonical"]),
                identity_key=identity_key(
                    str(row["entity_type"]), str(row["canonical"]), case_sensitive=False
                ),
                occurrences=tuple(
                    Occurrence(int(s), int(e), str(row["canonical"]), "restored", 1.0)
                    for s, e in spans
                ),
                detectors=frozenset(row.get("detectors", ())),
                max_confidence=float(row.get("max_confidence", 1.0)),
            )
            store._by_placeholder[entry.placeholder] = entry
            store._by_identity[entry.identity_key] = entry
            prefix = entry.placeholder_prefix
            parsed = store.format.parse(entry.placeholder)
            if parsed:
                store._counters[prefix] = max(store._counters.get(prefix, 0), parsed[1])
        return store

    def to_safe_summary(self) -> dict[str, object]:
        by_type: dict[str, int] = {}
        for entry in self._by_placeholder.values():
            by_type[entry.entity_type] = by_type.get(entry.entity_type, 0) + 1
        return {
            "conversation_id": self.conversation_id,
            "total": len(self._by_placeholder),
            "by_type": dict(sorted(by_type.items())),
            "occurrences": sum(len(e.occurrences) for e in self._by_placeholder.values()),
            "ambiguous": sum(1 for e in self._by_placeholder.values() if e.alias_candidates),
        }

    def __repr__(self) -> str:  # never include values
        return f"MappingStore(conversation={self.conversation_id!r}, entries={len(self)})"
