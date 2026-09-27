"""Run reports.

The prototype's reports embedded the model's full answer, with real names, in
a JSON file next to the source. This version omits content by default: you must
pass ``--include-content`` to get it, and the mapping is only ever written when
``--include-mapping`` is given as well.

The four timing keys the prototype emitted are preserved so existing consumers
keep working, with the honest breakdown added alongside.
"""

from __future__ import annotations

import json
import platform
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import Settings
from .gateway import GatewayResult

SCHEMA_VERSION = 2


def _git_commit() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _git_dirty() -> bool | None:
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return bool(out.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return None


def provenance(settings: Settings, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Machine and configuration context, so a result can be interpreted later."""
    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "git_commit": _git_commit(),
        "git_dirty": _git_dirty(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "config": settings.redacted_dict(),
        **(dict(extra) if extra else {}),
    }


def build_report(
    result: GatewayResult,
    settings: Settings,
    *,
    input_path: Path | None = None,
    sanitized_path: Path | None = None,
    include_content: bool = False,
    include_mapping: bool = False,
) -> dict[str, Any]:
    outcome = result.sanitize
    store = result.store
    reid = result.reidentification

    by_detector: dict[str, int] = {}
    for entity in outcome.entities:
        by_detector[entity.detector] = by_detector.get(entity.detector, 0) + 1

    rejected: dict[str, int] = {}
    for item in outcome.aggregation.rejected:
        rejected[str(item.verdict)] = rejected.get(str(item.verdict), 0) + 1

    by_action: dict[str, int] = {}
    for decision in outcome.decisions:
        by_action[str(decision.action)] = by_action.get(str(decision.action), 0) + 1

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "provenance": provenance(settings),
        "status": result.status,
        "warnings": list(result.warnings),
        "conversation_id": store.conversation_id,
        "input_file": str(input_path) if input_path else None,
        "sanitized_input_file": str(sanitized_path) if sanitized_path else None,
        "input_chars": len(outcome.normalized.original),
        "normalized_chars": len(outcome.normalized.text),
        "sanitized_chars": len(outcome.sanitized_text),
        "output_chars": len(result.output),
        "entity_count": len(store),
        "transcript": {
            "format": outcome.parsed.format,
            "speaker_labels": len(outcome.parsed.speaker_labels),
            "participants": len(outcome.registry),
        },
        "detection": {
            "candidates": outcome.aggregation.stats.get("candidates_in", 0),
            "final": len(outcome.entities),
            "by_detector": dict(sorted(by_detector.items())),
            "rejected": dict(sorted(rejected.items())),
            "degraded_detectors": list(outcome.degraded_detectors),
        },
        "policy": {"by_action": dict(sorted(by_action.items()))},
        "mapping": store.to_safe_summary(),
        "normalization": dict(outcome.normalized.stats),
        "injection": {"neutralized": outcome.injected},
        "performance": result.timings.to_dict(),
    }

    if reid is not None:
        report["reidentification"] = {
            "status": reid.status,
            "restored": len(reid.restored),
            "unique_restored": reid.stats.get("unique_restored", 0),
            "unrestored": list(reid.unrestored),
            "hallucinated_placeholders": list(reid.unknown),
            "drift": [
                {"kind": f.kind, "in_store": f.in_store, "start": f.start} for f in reid.drift
            ],
            "leaks": [
                {"kind": f.match_kind, "severity": f.severity, "entity_type": f.entity_type}
                for f in reid.leaks
            ],
            "llm_retries": result.llm_retries,
        }

    # Case variants are surfaced because canonical restoration returns the
    # first-seen spelling, which is the one documented lossy edge.
    variants = [
        {"placeholder": e.placeholder, "variants": len(e.variants)}
        for e in store.entries()
        if len(e.variants) > 1
    ]
    report["case_variants"] = variants

    if include_content:
        report["sanitized_input"] = outcome.sanitized_text
        report["result"] = result.output
    if include_mapping:
        # Only ever on an explicit opt-in. This is the secret.
        report["mapping_values"] = store.to_dict(include_values=True)

    return report


def write_report(report: Mapping[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    return path
