"""Markdown rendering of evaluation results.

Rendered from ``metrics.json`` only, never hand-written.

Two presentation rules are enforced here rather than left to prose:

* a measurement that was not taken renders as ``not measured``, never ``0``
  and never a bare dash. A skipped configuration renders on its own visible
  row with its reason, so an absent Qwen is *shown* rather than omitted.
* a per-type figure with fewer than ten supporting spans renders as raw
  counts, because an F1 over six phone numbers has a confidence interval wider
  than any difference it could show.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .metrics import MIN_SUPPORT_FOR_F1

NOT_MEASURED = "not measured"


def _fmt(value: Any) -> str:
    if value is None:
        return NOT_MEASURED
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def _row(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def render_markdown(payload: Mapping[str, Any]) -> str:
    dataset = payload.get("dataset", {})
    prov = payload.get("provenance", {})
    configs = payload.get("configs", [])
    no_speaker = payload.get("excluding_speaker_lines", {})

    lines: list[str] = ["# Detection evaluation", ""]

    # -- the caveats, before the numbers ------------------------------------
    lines += [
        "> **How to read this.** Labels were produced by an AI assistant reading",
        "> each excerpt, **not** by a human annotator, and have not been",
        "> human-verified. No inter-annotator agreement was measured, so none is",
        "> reported. These figures describe how the detector configurations",
        "> differ from one another on this corpus; they are not a validated",
        "> benchmark and should not be quoted as accuracy claims.",
        "",
        f"Gold set: **{dataset.get('documents', 0)} excerpts**, "
        f"**{dataset.get('entities_scored', 0)} scored spans** "
        f"({dataset.get('entities_excluded_ambiguous', 0)} excluded as ambiguous). "
        f"{dataset.get('independent_fraction', 0):.0%} of spans were identified "
        "independently of the detectors.",
        "",
        f"Commit `{prov.get('git_commit')}`"
        + (" (working tree dirty)" if prov.get("git_dirty") else "")
        + f", {prov.get('platform', '')}, {prov.get('generated_at_utc', '')}.",
        "",
    ]

    if dataset.get("circularity_warning"):
        lines += [f"> **Circularity warning:** {dataset['circularity_warning']}", ""]

    # -- the headline table --------------------------------------------------
    lines += [
        "## Configurations",
        "",
        "`Leak docs` is the number of excerpts where at least one gold entity was",
        "missed entirely, and is the figure to read first: for a privacy gateway a",
        "single missed entity matters more than an aggregate F1.",
        "",
        _row(
            [
                "Cfg", "Detectors", "Leak docs", "Char recall",
                "Strict P", "Strict R", "Strict F1", "Overlap F1", "No-speaker F1",
            ]
        ),
        _row(["---"] * 9),
    ]

    for config in configs:
        if config.get("status") != "ok":
            lines.append(
                _row(
                    [
                        config["key"],
                        config["label"],
                        f"*skipped: {config.get('reason', 'unavailable')}*",
                        *[NOT_MEASURED] * 6,
                    ]
                )
            )
            continue
        metrics = config.get("metrics") or {}
        strict = metrics.get("strict", {})
        overlap = metrics.get("overlap_typed", {})
        ns = (no_speaker.get(config["key"]) or {}).get("strict", {})
        lines.append(
            _row(
                [
                    config["key"],
                    config["label"],
                    f"{metrics.get('docs_with_any_leak', 0)}/{metrics.get('docs_total', 0)}",
                    _fmt(metrics.get("char_recall")),
                    _fmt(strict.get("precision")),
                    _fmt(strict.get("recall")),
                    _fmt(strict.get("f1")),
                    _fmt(overlap.get("f1")),
                    _fmt(ns.get("f1")),
                ]
            )
        )

    lines += [
        "",
        "A dash never appears in this table: a cell reads `not measured` when the",
        "measurement was not taken. `not measured` is not zero.",
        "",
        "### Two things these numbers do not say",
        "",
        "**This measures detection, not protection.** The sweep stops after entity",
        "aggregation; the policy engine does not run. Several false positives below",
        "are entities the policy layer would then *allow* rather than protect --",
        "`Cortana` is the clearest case, an allowlisted product name that Presidio",
        "reports as a person. Precision against what actually reaches the mapping is",
        "therefore higher than the precision column shows.",
        "",
        "**The participant registry is weaker here than in production.** It is built",
        "per excerpt, so a name that speaks elsewhere in the meeting but only appears",
        "in the body of this excerpt is not a known participant. Several `Ahmed",
        "Hamed` false negatives are exactly this: the excerpt's registry knows only",
        "`Ahmed Farid`, so the bare token `Ahmed` matches instead of the full name.",
        "Whole-document runs do not have this limitation, so registry recall is",
        "understated across every configuration that includes it.",
        "",
    ]

    skipped = [c for c in configs if c.get("status") != "ok"]
    if skipped:
        lines += ["### Skipped configurations", ""]
        for config in skipped:
            lines.append(f"- **{config['key']} ({config['label']})** — {config.get('reason')}")
        lines.append("")

    # -- per type ------------------------------------------------------------
    counts = dataset.get("per_type_counts", {})
    if counts:
        lines += [
            "## Gold set composition",
            "",
            _row(["Type", "Spans"]),
            _row(["---", "---"]),
        ]
        for entity_type, count in counts.items():
            note = " *(too few for F1)*" if count < MIN_SUPPORT_FOR_F1 else ""
            lines.append(_row([entity_type, f"{count}{note}"]))
        lines += [
            "",
            "PERSON dominates because speaker-label lines are the majority class in",
            "any transcript. That is why the `No-speaker F1` column exists: it",
            "removes every span sitting on a structural speaker line, from both the",
            "gold set and the predictions.",
            "",
        ]

    # -- per-config detail ----------------------------------------------------
    for config in configs:
        if config.get("status") != "ok":
            continue
        metrics = config.get("metrics") or {}
        by_type = metrics.get("by_type", {})
        if not by_type:
            continue
        lines += [f"### {config['key']} — {config['label']}", "", _row(["Type", "TP", "FP", "FN", "F1"]), _row(["---"] * 5)]
        for entity_type, values in by_type.items():
            f1 = values.get("f1")
            label = _fmt(f1) if "f1" in values else "*counts only*"
            lines.append(
                _row(
                    [
                        entity_type,
                        str(values.get("tp", 0)),
                        str(values.get("fp", 0)),
                        str(values.get("fn", 0)),
                        label,
                    ]
                )
            )
        lines += [
            "",
            f"False positives: {metrics.get('false_positive_count', 0)}, "
            f"false negatives: {metrics.get('false_negative_count', 0)}. "
            f"Both are listed with surrounding context in `errors/{config['key']}_*.jsonl`.",
            "",
        ]

    seconds = payload.get("detector_seconds", {})
    if seconds:
        lines += ["## Detector cost", "", _row(["Detector", "Seconds (whole gold set)"]), _row(["---", "---"])]
        for name, value in seconds.items():
            lines.append(_row([name, f"{value:.2f}"]))
        lines.append("")

    return "\n".join(lines)
