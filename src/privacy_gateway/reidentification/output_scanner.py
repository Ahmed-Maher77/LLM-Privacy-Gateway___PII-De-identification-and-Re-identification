"""Leak scanning: did a protected value survive into text it should not be in?

Used at two points, with deliberately different semantics.

**Pre-send.** Run against the sanitized prompt immediately before it leaves the
process. A hit means detection ran but replacement failed, and we are one HTTP
call away from an unrecoverable disclosure. This gate is *not* governed by the
fail mode -- there is no such thing as failing open on a transmission that has
already happened.

**Post-response.** Run against the model's reply before restoration. A hit means
the model reproduced something we believed we had removed. Under fail-closed the
reply is withheld entirely; under fail-open it is returned with findings
attached.

For person names, individual tokens of four or more characters are also
searched. That is what catches the partial-name leaks visible in the
prototype's SME run (``tests/regression/fixtures/prototype_v0/sme_meeting.v0_run.json``),
where bare ``Sarah``, ``Michael`` and ``James`` survived into the final answer
even though the full names had been replaced.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from ..entities.taxonomy import PERSON_LIKE
from ..errors import SanitizationLeakError
from ..pseudonymization.mapping_store import MappingEntry, MappingStore

MatchKind = Literal["exact", "casefold", "name_token", "digit_run"]
Severity = Literal["critical", "warning"]

DEFAULT_TOKEN_MIN_CHARS = 4
_DIGIT_RUN_MIN = 6
_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)
_DIGITS_RE = re.compile(r"\d+")


@dataclass(frozen=True, slots=True)
class LeakFinding:
    placeholder: str
    entity_type: str
    start: int
    end: int
    match_kind: MatchKind
    severity: Severity

    def __repr__(self) -> str:  # never include the leaked value
        return (
            f"LeakFinding({self.entity_type} {self.start}:{self.end} "
            f"kind={self.match_kind} severity={self.severity} via {self.placeholder})"
        )


class OutputScanner:
    """Searches text for any value the mapping is supposed to be hiding."""

    def __init__(
        self,
        store: MappingStore,
        *,
        token_min_chars: int = DEFAULT_TOKEN_MIN_CHARS,
        scan_name_tokens: bool = True,
        scan_digit_runs: bool = True,
    ) -> None:
        self.store = store
        self.token_min_chars = token_min_chars
        self.scan_name_tokens = scan_name_tokens
        self.scan_digit_runs = scan_digit_runs
        self._targets = self._build_targets()

    def _build_targets(self) -> tuple[tuple[re.Pattern[str], MappingEntry, MatchKind, Severity], ...]:
        out: list[tuple[re.Pattern[str], MappingEntry, MatchKind, Severity]] = []
        for value, entry in self.store.sensitive_values():
            value = value.strip()
            if len(value) < 2:
                continue
            flags = 0 if entry.case_sensitive else re.IGNORECASE
            kind: MatchKind = "exact" if entry.case_sensitive else "casefold"
            out.append(
                (
                    re.compile(r"(?<!\w)" + re.escape(value) + r"(?!\w)", flags),
                    entry,
                    kind,
                    "critical",
                )
            )

            if self.scan_name_tokens and entry.entity_type in PERSON_LIKE:
                for token in _WORD_RE.findall(value):
                    if len(token) >= self.token_min_chars:
                        out.append(
                            (
                                re.compile(r"(?<!\w)" + re.escape(token) + r"(?!\w)", re.IGNORECASE),
                                entry,
                                "name_token",
                                # A single common forename could be coincidence,
                                # so this is a warning rather than a hard block.
                                "warning",
                            )
                        )

            if self.scan_digit_runs:
                for run in _DIGITS_RE.findall(value):
                    if len(run) >= _DIGIT_RUN_MIN:
                        out.append(
                            (
                                re.compile(r"(?<!\d)" + re.escape(run) + r"(?!\d)"),
                                entry,
                                "digit_run",
                                "critical",
                            )
                        )
        # Longest first so the most specific finding is reported.
        out.sort(key=lambda t: -len(t[0].pattern))
        return tuple(out)

    def scan(self, text: str) -> tuple[LeakFinding, ...]:
        if not text or not self._targets:
            return ()
        findings: list[LeakFinding] = []
        claimed: list[tuple[int, int]] = []
        for pattern, entry, kind, severity in self._targets:
            for m in pattern.finditer(text):
                if any(s <= m.start() and m.end() <= e for s, e in claimed):
                    continue  # already reported by a longer, more specific match
                claimed.append(m.span())
                findings.append(
                    LeakFinding(
                        placeholder=entry.placeholder,
                        entity_type=entry.entity_type,
                        start=m.start(),
                        end=m.end(),
                        match_kind=kind,
                        severity=severity,
                    )
                )
        findings.sort(key=lambda f: f.start)
        return tuple(findings)

    def assert_clean(self, text: str, context: str) -> None:
        """Raise if any protected value is present. Never fails open."""
        critical = [f for f in self.scan(text) if f.severity == "critical"]
        if critical:
            raise SanitizationLeakError(
                count=len(critical),
                entity_types=tuple(f.entity_type for f in critical),
                context=context,
            )

