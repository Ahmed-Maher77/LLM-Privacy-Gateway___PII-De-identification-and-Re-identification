"""Markdown and JSON reports for a corpus evaluation run.

The report this replaces printed the placeholder vault with a length check for
masking -- ``val if len(val) <= 20 else val[:10] + "..." + val[-6:]`` -- which
left everything shorter than twenty-one characters in the clear. Names, phone
numbers and record ids are all shorter than that, so the table was a plaintext
PII dump, and the full unified diff beneath it printed the original lines
verbatim. Neither was gated, and the same values went to stdout, where CI would
have captured them permanently.

Here masking is the default on every path, uses the helpers that already got
this right elsewhere in the codebase, and the unmasked form requires an
explicit flag that also restricts the file mode.
"""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Sequence

from pii.reporting import WARNING_TEXT, write_text
from pii.residual import digest, mask


def mask_values(values: Sequence[str], *, include_secrets: bool) -> list[str]:
    """Mask a list of raw values for display.

    Leaks and over-redactions *are* the sensitive values -- a leak is by
    definition PII that survived redaction -- so they get the same treatment
    as the vault table rather than being printed because they are short.
    """
    if include_secrets:
        return list(values)
    return [mask(v) for v in values]


def vault_table(mapping: dict[str, str], *, include_secrets: bool) -> list[str]:
    if not mapping:
        return []
    lines = ["#### Placeholder vault", ""]
    if include_secrets:
        lines += ["| Placeholder | Len | Value |", "|---|---|---|"]
        for placeholder, value in sorted(mapping.items()):
            lines.append(f"| `{placeholder}` | {len(value)} | `{value}` |")
    else:
        lines += ["| Placeholder | Len | Preview | Digest |", "|---|---|---|---|"]
        for placeholder, value in sorted(mapping.items()):
            lines.append(f"| `{placeholder}` | {len(value)} | `{mask(value)}` | `{digest(value)}` |")
    lines.append("")
    return lines


def render_diff(source: str, sanitized: str, *, include_secrets: bool) -> list[str]:
    """Show what changed without reprinting the original.

    A unified diff of original against sanitized is a complete copy of the PII
    by construction: every removed line is the unredacted one. By default only
    the sanitized side is shown, which is the side that is safe to read.
    """
    if include_secrets:
        diff = "\n".join(
            difflib.unified_diff(
                source.splitlines(), sanitized.splitlines(),
                fromfile="original", tofile="sanitized", lineterm="", n=1,
            )
        )
        return ["#### Unified diff (original -> sanitized)", "```diff", diff or " (no changes)", "```", ""]

    changed = [
        line for line in difflib.unified_diff(
            source.splitlines(), sanitized.splitlines(), lineterm="", n=0
        )
        if line.startswith("+") and not line.startswith("+++")
    ]
    body = "\n".join(line[1:] for line in changed) or " (no changes)"
    return [
        "#### Redacted lines (sanitized side only)",
        f"_{len(changed)} line(s) changed. Original withheld -- rerun with `--include-secrets` to see it._",
        "```",
        body,
        "```",
        "",
    ]


def build_markdown(scores: Sequence, summary: dict, *, include_secrets: bool) -> str:
    micro = summary.get("micro", {})
    corpus = summary.get("corpus", {})
    lines: list[str] = []

    if include_secrets:
        lines += [f"> {WARNING_TEXT}", ""]

    lines += [
        "# Redaction evaluation",
        "",
        f"- **Documents**: {corpus.get('documents', len(scores))}",
        f"- **Gold spans**: {corpus.get('gold_spans', 0)}",
        f"- **Exhaustively labelled**: {corpus.get('gold_complete', 0)}/{corpus.get('documents', 0)}",
        f"- **Micro precision**: `{micro.get('precision', 0):.4f}`",
        f"- **Micro recall**: `{micro.get('recall', 0):.4f}`",
        f"- **Micro F1**: `{micro.get('f1', 0):.4f}`",
        f"- **TP / FP / FN**: `{micro.get('tp', 0)}` / `{micro.get('fp', 0)}` / `{micro.get('fn', 0)}`",
        f"- **Unverified predictions**: `{micro.get('unverified', 0)}`",
        f"- **Substring-gate leaks**: `{summary.get('total_leaks', 0)}`",
        f"- **Boundary exact rate**: `{summary.get('boundary_exact_rate', 0):.4f}`",
        "",
    ]

    if micro.get("unverified"):
        lines += [
            "> Precision is a **lower bound**: "
            f"{micro['unverified']} prediction(s) sit on documents whose gold is not "
            "exhaustive, so they are reported separately rather than counted as "
            "correct or incorrect.",
            "",
        ]

    policy = summary.get("policy")
    if policy:
        lines += [
            "## Policy",
            "",
            f"- **Profile**: `{policy.get('profile')}`",
            f"- **Redacted**: {', '.join(f'`{t}`' for t in policy.get('redacted', []))}",
            f"- **Not redacted**: {', '.join(f'`{t}`' for t in policy.get('not_redacted', []))}",
        ]
        if policy.get("overrides"):
            overrides = ", ".join(f"`{k}={v}`" for k, v in policy["overrides"].items())
            lines.append(f"- **Overrides**: {overrides}")
        lines.append("")

    lines += ["## Detectors", ""]
    for detector in summary.get("detectors", []):
        state = "available" if detector.get("available") else f"MISSING ({detector.get('reason')})"
        model = detector.get("model_id", "")
        version = detector.get("package_version", "")
        lines.append(f"- `{detector.get('name')}` — {state}" + (f" — `{model}` {version}" if model else ""))
    lines.append("")

    lines += ["## Per-label", "", "| Label | P | R | F1 | TP | FP | FN |", "|---|---|---|---|---|---|---|"]
    for label, row in summary.get("by_label", {}).items():
        lines.append(
            f"| `{label}` | {row['precision']:.3f} | {row['recall']:.3f} | {row['f1']:.3f} "
            f"| {row['tp']} | {row['fp']} | {row['fn']} |"
        )
    lines.append("")

    lines += [
        "## Per-document",
        "",
        "| Document | F1 | TP | FP | FN | Unver | Entities | Status | Gold complete | ms |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for score in scores:
        c = score.counts
        f1 = f"{score.f1:.3f}" if score.measured else "n/a"
        lines.append(
            f"| `{score.name}` | {f1} | {c.tp} | {c.fp} | {c.fn} | {c.unverified} "
            f"| {score.entities} | {score.status} | {'yes' if score.gold_complete else 'no'} "
            f"| {score.latency_s * 1000:.0f} |"
        )
    lines.append("")

    failures = [(s.name, s.hard_failures) for s in scores if s.hard_failures]
    if failures:
        lines += ["## Hard failures", ""]
        for name, problems in failures:
            lines.append(f"- `{name}`: {'; '.join(problems)}")
        lines.append("")

    lines += ["## Detailed breakdowns", ""]
    for score in scores:
        lines.append(f"### `{score.name}`")
        lines.append("")
        c = score.counts
        lines.append(
            f"- P/R/F1: `{score.span_precision:.3f}` / `{score.span_recall:.3f}` / "
            + (f"`{score.f1:.3f}`" if score.measured else "`n/a`")
        )
        lines.append(f"- TP/FP/FN/unverified: `{c.tp}` / `{c.fp}` / `{c.fn}` / `{c.unverified}`")
        lines.append(f"- Entities: `{score.entities}` · Latency: `{score.latency_s:.3f}s` · Status: `{score.status}`")
        if score.json_valid is not None:
            lines.append(f"- JSON valid after redaction: `{'yes' if score.json_valid else 'NO'}`")
        if score.leaks:
            lines.append(f"- **Leaks**: `{mask_values(score.leaks, include_secrets=include_secrets)}`")
        if score.over_redactions:
            lines.append(
                f"- Over-redactions: `{mask_values(score.over_redactions, include_secrets=include_secrets)}`"
            )
        if score.cluster and not score.cluster.ok:
            lines.append(f"- Wrong merges: `{score.cluster.wrong_merges}`")
            lines.append(f"- Missed merges: `{score.cluster.missed_merges}`")
        lines.append("")
        lines += vault_table(score.mapping, include_secrets=include_secrets)
        lines += render_diff(score.source, score.sanitized, include_secrets=include_secrets)

    return "\n".join(lines)


def build_json(scores: Sequence, summary: dict, *, include_secrets: bool) -> dict:
    payload = dict(summary)
    payload["false_redactions"] = [
        {
            "document": g["document"],
            "label": g["label"],
            "text": g["text"] if include_secrets else mask(g["text"]),
            "count": g["count"],
            "source": g["source"],
            "line": g["line"],
        }
        for g in _false_redactions(scores)
    ]
    payload["contains_secrets"] = include_secrets
    return payload


def _false_redactions(scores: Sequence) -> list[dict]:
    from tools.evaluate import false_redaction_groups

    return false_redaction_groups(list(scores))


def write_reports(
    scores: Sequence,
    summary: dict,
    *,
    markdown_path: Path,
    json_path: Path,
    include_secrets: bool = False,
) -> None:
    markdown = build_markdown(scores, summary, include_secrets=include_secrets)
    write_text(markdown_path, markdown, contains_secrets=include_secrets)

    payload = json.dumps(build_json(scores, summary, include_secrets=include_secrets), indent=2)
    write_text(json_path, payload, contains_secrets=include_secrets)

    print(f"\nReport written to {markdown_path}")
    print(f"JSON written to {json_path}")
    if include_secrets:
        print(f"  !! {WARNING_TEXT}")
