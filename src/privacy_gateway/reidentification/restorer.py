"""Restoration: placeholders back to values, exactly and only.

A single ``re.sub`` pass over the placeholder grammar. Two bug classes die with
that choice:

* **Prefix collision.** Sequential ``str.replace`` of ``<PER_1>`` before
  ``<PER_11>`` corrupts the latter. The prototype worked around this by sorting
  the mapping by placeholder length; a single anchored pass makes it impossible.
* **Cascading re-substitution.** Sequential replacement rescans text it just
  inserted, so a restored value that happens to look like a placeholder gets
  rewritten again. One ``sub`` pass never revisits its own output -- which is
  also what makes the injection defence airtight.

A well-formed placeholder that is not in this conversation's store is
*hallucinated*. The prototype's own output contains three of them
(``<PER_10>``, ``<PER_11>``, ``<PER_12>``, none of which appear in its sanitized
input). They are never guessed at; by default they are redacted and reported.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

from ..policy.engine import PolicyEngine
from ..pseudonymization.mapping_store import MappingStore
from .drift import DriftFinding, DriftScanner
from .output_scanner import LeakFinding, OutputScanner

UnknownAction = Literal["keep", "redact", "fail"]
Status = Literal["ok", "degraded", "blocked"]

UNRESOLVED_MARKER = "[UNRESOLVED_PLACEHOLDER]"


@dataclass(frozen=True, slots=True)
class ReidentificationResult:
    text: str
    status: Status = "ok"
    restored: tuple[str, ...] = ()
    unrestored: tuple[str, ...] = ()
    unknown: tuple[str, ...] = ()
    drift: tuple[DriftFinding, ...] = ()
    leaks: tuple[LeakFinding, ...] = ()
    stats: Mapping[str, int] = field(default_factory=dict)

    @property
    def clean(self) -> bool:
        return not self.unknown and not self.drift and not self.leaks


class Reidentifier:
    """Restores placeholders using one trusted, conversation-scoped mapping."""

    def __init__(
        self,
        store: MappingStore,
        policy: PolicyEngine | None = None,
        *,
        unknown_action: UnknownAction = "redact",
        scan_output: bool = True,
        scan_drift: bool = True,
    ) -> None:
        self.store = store
        self.policy = policy
        self.unknown_action = unknown_action
        self.scan_output = scan_output
        self.scan_drift = scan_drift
        self._scanner = OutputScanner(store) if scan_output else None
        self._drift = DriftScanner(store) if scan_drift else None

    def restore(self, text: str, *, conversation_id: str | None = None) -> ReidentificationResult:
        # Cross-conversation access is refused outright: one conversation's
        # placeholder must be inert in another.
        if conversation_id is not None:
            self.store.require_conversation(conversation_id)

        leaks = self._scanner.scan(text) if self._scanner else ()
        drift = self._drift.scan(text) if self._drift else ()

        restored: list[str] = []
        unknown: list[str] = []

        def _substitute(match) -> str:
            token = match.group()
            entry = self.store.get(token)
            if entry is None:
                unknown.append(token)
                return UNRESOLVED_MARKER if self.unknown_action == "redact" else token
            if self.policy is not None:
                rule = self.policy.rule_for(entry.entity_type)
                if not rule.restorable:
                    return token
            restored.append(token)
            return entry.canonical

        out = self.store.format.pattern.sub(_substitute, text)

        seen = set(restored)
        unrestored = tuple(sorted(p for p in self.store.placeholders() if p not in seen))

        status: Status = "ok"
        if unknown or drift or leaks:
            status = "degraded"

        stats = {
            "restored": len(restored),
            "unique_restored": len(seen),
            "unknown": len(unknown),
            "unrestored": len(unrestored),
            "drift": len(drift),
            "leaks": len(leaks),
        }
        return ReidentificationResult(
            text=out,
            status=status,
            restored=tuple(restored),
            unrestored=unrestored,
            unknown=tuple(unknown),
            drift=drift,
            leaks=leaks,
            stats=stats,
        )
