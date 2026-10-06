"""Allow and deny lists.

An allowlist entry says "detected, but not worth protecting". Public product
and place names identify nobody, and pseudonymizing them destroys the meaning
of a sentence while protecting nothing -- a summary in which every tool and
city is a placeholder is useless.

Entries are type-scoped by default (``ORGANIZATION<tab>Microsoft``). A bare
value with no type applies to every type, which is what you want for a product
name that a generic NER model keeps labelling as a person -- "Cortana" is the
motivating case: the prototype detected it as PERSON and corrupted it into
``<PER_11>rtana``.

The denylist is the operator's override in the other direction and is checked
first, so "this specific client name must never leave" always wins.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

#: Applies to every entity type.
ANY_TYPE = "*"


@dataclass(frozen=True, slots=True)
class Allowlist:
    """Case-insensitive, optionally type-scoped set of exempt values."""

    entries: frozenset[tuple[str, str]] = field(default_factory=frozenset)

    @classmethod
    def parse(cls, lines: Iterable[str]) -> Allowlist:
        out: set[tuple[str, str]] = set()
        for raw in lines:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if "\t" in line:
                entity_type, _, value = line.partition("\t")
                entity_type, value = entity_type.strip().upper(), value.strip()
            else:
                entity_type, value = ANY_TYPE, line
            if value:
                out.add((entity_type, value.casefold()))
        return cls(frozenset(out))

    @classmethod
    def load(cls, path: Path | str) -> Allowlist:
        path = Path(path)
        if not path.exists():
            return cls()
        return cls.parse(path.read_text(encoding="utf-8").splitlines())

    def __len__(self) -> int:
        return len(self.entries)

    def __contains__(self, item: tuple[str, str]) -> bool:
        entity_type, value = item
        key = value.casefold()
        return (entity_type.upper(), key) in self.entries or (ANY_TYPE, key) in self.entries

    def matches(self, entity_type: str, value: str) -> bool:
        return (entity_type, value) in self
