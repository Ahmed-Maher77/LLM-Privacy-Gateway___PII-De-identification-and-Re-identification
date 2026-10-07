"""Build run reports that are safe to keep, commit and share.

The previous report wrote the full placeholder mapping -- real SSN, date of
birth, emails, phone numbers -- plus the restored LLM output into a JSON file
in a tracked directory. A tool whose job is to keep PII away from third parties
should not be the thing that writes it to disk.

Everything here is redacted by default. A reviewer needs *locatability* --
rule, line, column, masked preview -- not the value itself.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from .residual import Finding, digest, mask

if TYPE_CHECKING:  # pragma: no cover
    from .middleware import AnonymizationResult

WARNING_TEXT = (
    "This file contains REAL personal data. Do not commit it, attach it to a "
    "ticket, or upload it anywhere."
)


def make_salt() -> bytes:
    """Fresh per-report salt.

    Unsalted digests are not redaction. A SHA-256 of a social security number
    covers only 10^9 possibilities and falls to a dictionary attack in about a
    second, so correlating digests across runs has to be opted into rather than
    being the accidental default.
    """
    return secrets.token_bytes(16)


def summarize_mapping(
    result: AnonymizationResult,
    *,
    reveal: bool = False,
    salt: bytes = b"",
) -> dict:
    """Describe what was replaced without saying what it was."""
    by_type: dict[str, int] = {}
    entries: list[dict] = []

    for placeholder, value in result.mapping.items():
        label = placeholder.strip("{}").rsplit("_", 1)[0]
        by_type[label] = by_type.get(label, 0) + 1
        entry = {
            "placeholder": placeholder,
            "type": label,
            "value_digest": digest(value, salt=salt),
            "value_length": len(value),
            "value_preview": mask(value),
            "occurrences": result.sanitized.count(placeholder),
        }
        if reveal:
            entry["value"] = value
        entries.append(entry)

    return {
        "entity_count": len(result.mapping),
        "by_type": dict(sorted(by_type.items())),
        "entries": entries,
    }


def summarize_findings(
    findings: Sequence[Finding],
    *,
    reveal: bool = False,
    salt: bytes = b"",
) -> list[dict]:
    """Serialize residual findings without their values."""
    items: list[dict] = []
    for finding in findings:
        item = {
            "rule": finding.rule,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": round(finding.confidence, 2),
            "line": finding.line,
            "column": finding.column,
            "value_digest": digest(finding.text, salt=salt),
            "value_preview": finding.preview,
            "reason": finding.reason,
            "keyword": finding.keyword,
        }
        if finding.suppressed_by:
            item["suppressed_by"] = finding.suppressed_by
        if reveal:
            item["value"] = finding.text
        items.append(item)
    return items


def summarize_leaks(
    leaks: Sequence[dict],
    *,
    reveal: bool = False,
    salt: bytes = b"",
) -> list[dict]:
    """``leaks[].value`` is raw PII, so it never survives serialization."""
    items: list[dict] = []
    for leak in leaks:
        value = str(leak.get("value", ""))
        item = {
            "origin": leak.get("origin"),
            "severity": leak.get("severity"),
            "occurrences": leak.get("occurrences"),
            "value_digest": digest(value, salt=salt),
            "value_preview": mask(value),
        }
        if reveal:
            item["value"] = value
        items.append(item)
    return items


def write_text(path: Path, payload: str, *, contains_secrets: bool) -> None:
    """Write an artefact, restricting permissions when secrets are inside.

    ``0o600`` is close to advisory on Windows, which is this project's home
    platform -- the control that actually bites there is the parent directory
    ACL. The mode is still set for the POSIX case, and the README says plainly
    which one is load-bearing where.

    Named for text rather than JSON because the markdown evaluation report
    needs exactly the same handling, and previously went out through a bare
    ``write_text`` with no mode at all.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if not contains_secrets:
        path.write_text(payload, encoding="utf-8")
        return

    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(payload)
