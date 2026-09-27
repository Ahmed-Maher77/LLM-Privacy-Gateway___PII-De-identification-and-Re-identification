"""Evaluate and compare production transcripts against ground-truth expectations.

Runs PIIMiddleware across diverse production-grade transcripts simulating real-world
workloads (healthcare, fintech, devops, legal, customer support, HR, multilingual,
noisy ASR, API webhooks, and controls).

Generates:
1. Sanitized transcripts saved to test_data/production_simulations/sanitized/
2. Formatted CLI scorecard table
3. Markdown benchmark report with side-by-side diffs at reports/production_simulation_report.md
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
import time
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from pii import PIIMiddleware  # noqa: E402

DEFAULT_SIM_DIR = PROJECT_ROOT / "test_data" / "production_simulations"
DEFAULT_SANITIZED_DIR = DEFAULT_SIM_DIR / "sanitized"
DEFAULT_REPORT_MD = PROJECT_ROOT / "reports" / "production_simulation_report.md"


@dataclass
class ScenarioEvaluation:
    name: str
    source: str
    sanitized: str
    mapping: dict[str, str]
    expected: dict
    elapsed_seconds: float
    leaks: list[str] = field(default_factory=list)
    over_redactions: list[str] = field(default_factory=list)
    split_entities: list[str] = field(default_factory=list)
    integrity_issues: list[str] = field(default_factory=list)
    json_valid: bool | None = None

    @property
    def expected_redactions(self) -> int:
        return len(self.expected.get("must_redact", []))

    @property
    def expected_keeps(self) -> int:
        return len(self.expected.get("must_keep", []))

    @property
    def recall(self) -> float:
        if not self.expected_redactions:
            return 1.0
        return max(0.0, 1.0 - (len(self.leaks) / self.expected_redactions))

    @property
    def precision(self) -> float:
        if not self.expected_keeps:
            return 1.0
        return max(0.0, 1.0 - (len(self.over_redactions) / self.expected_keeps))

    @property
    def is_clean(self) -> bool:
        return not (
            self.leaks
            or self.over_redactions
            or self.split_entities
            or self.integrity_issues
            or (self.json_valid is False)
        )


def _contains_token(haystack: str, needle: str) -> bool:
    """Whole-token containment check."""
    return re.search(rf"(?<!\w){re.escape(needle)}(?!\w)", haystack) is not None


def extract_json_blocks(text: str) -> list[str]:
    """Find JSON blocks in text by scanning for outermost balanced curly braces that are not template placeholders."""
    blocks: list[str] = []
    i = 0
    while i < len(text):
        if text[i : i + 2] == "{{":
            close_idx = text.find("}}", i + 2)
            if close_idx != -1:
                i = close_idx + 2
                continue
            else:
                i += 2
                continue
        if text[i] == "{":
            depth = 0
            start = i
            in_string = False
            escape = False
            for j in range(start, len(text)):
                c = text[j]
                if c == '"' and not escape:
                    in_string = not in_string
                elif c == "\\" and in_string:
                    escape = not escape
                    continue
                elif not in_string:
                    if text[j : j + 2] == "{{":
                        continue
                    if c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            candidate = text[start : j + 1]
                            if "\n" in candidate and ":" in candidate and '"' in candidate:
                                blocks.append(candidate)
                            i = j
                            break
                escape = False
        i += 1
    return blocks


def evaluate_single_transcript(
    name: str,
    source: str,
    expected: dict,
    middleware: PIIMiddleware,
) -> ScenarioEvaluation:
    start_time = time.perf_counter()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = middleware.analyze(source)
    elapsed = time.perf_counter() - start_time

    sanitized = result.sanitized
    eval_result = ScenarioEvaluation(
        name=name,
        source=source,
        sanitized=sanitized,
        mapping=result.mapping,
        expected=expected,
        elapsed_seconds=elapsed,
    )

    # 1. Recall Check: must_redact
    must_redact = expected.get("must_redact", [])
    for item in must_redact:
        val = item["value"] if isinstance(item, dict) else item
        if _contains_token(sanitized, val):
            eval_result.leaks.append(val)

    # 2. Precision Check: must_keep
    must_keep = expected.get("must_keep", [])
    for val in must_keep:
        # Check if the keep value survived in sanitized text
        if val not in sanitized:
            eval_result.over_redactions.append(val)

    # 3. Entity Consistency Check
    by_val: dict[str, set[str]] = {}
    for placeholder, val in result.mapping.items():
        by_val.setdefault(val, set()).add(placeholder)
    for val, placeholders in by_val.items():
        if len(placeholders) > 1:
            eval_result.split_entities.append(f"{val!r} -> {sorted(placeholders)}")

    for group in expected.get("same_entity", []):
        placeholders = {
            ph for ph, val in result.mapping.items() if any(item in val or val in item for item in group)
        }
        if len(placeholders) > 1:
            eval_result.split_entities.append(f"{group} -> {sorted(placeholders)}")

    # 4. Integrity Checks
    for opener, closer in (("(", ")"), ("[", "]"), ("{{", "}}")):
        if sanitized.count(opener) != sanitized.count(closer):
            eval_result.integrity_issues.append(f"unbalanced {opener}{closer}")
    if sanitized.count('"') % 2 != source.count('"') % 2:
        eval_result.integrity_issues.append("quote parity changed")
    if len(source.splitlines()) != len(sanitized.splitlines()):
        eval_result.integrity_issues.append("line count changed")
    if re.search(r"\}\}\w", sanitized) or re.search(r"\w\{\{", sanitized):
        eval_result.integrity_issues.append("placeholder glued mid-word")
    for match in re.finditer(r"\{\{([A-Z][A-Z0-9_]*_\d+)\}\}\s*\{\{\1\}\}", sanitized):
        eval_result.integrity_issues.append(f"duplicate adjacent placeholder {match.group(1)}")

    # 5. JSON Syntax Validation if document contains JSON block
    json_blocks = extract_json_blocks(sanitized)
    if json_blocks:
        eval_result.json_valid = True
        for block in json_blocks:
            try:
                json.loads(block)
            except Exception as e:
                eval_result.json_valid = False
                eval_result.integrity_issues.append(f"invalid JSON structure after sanitization: {e}")

    return eval_result


def generate_diff(source: str, sanitized: str) -> str:
    """Generate a clean unified diff between original and sanitized text."""
    src_lines = source.splitlines()
    san_lines = sanitized.splitlines()
    diff = list(difflib.unified_diff(src_lines, san_lines, fromfile="Original", tofile="Sanitized", lineterm=""))
    return "\n".join(diff[:60])  # limit diff length for readability


def build_markdown_report(evaluations: list[ScenarioEvaluation], run_duration: float) -> str:
    total_docs = len(evaluations)
    clean_docs = sum(1 for e in evaluations if e.is_clean)
    macro_recall = sum(e.recall for e in evaluations) / total_docs if total_docs else 1.0
    macro_precision = sum(e.precision for e in evaluations) / total_docs if total_docs else 1.0
    total_leaks = sum(len(e.leaks) for e in evaluations)
    total_over = sum(len(e.over_redactions) for e in evaluations)

    lines: list[str] = [
        "# Production Simulation Benchmark Report: PII De-identification & Evaluation",
        "",
        f"**Generated**: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Total Scenarios Evaluated**: {total_docs}  ",
        f"**Clean Scenarios**: {clean_docs}/{total_docs} ({clean_docs/total_docs*100:.1f}%)  ",
        f"**Macro Recall**: `{macro_recall*100:.2f}%` (Total Leaks: `{total_leaks}`)  ",
        f"**Macro Precision**: `{macro_precision*100:.2f}%` (Total Over-redactions: `{total_over}`)  ",
        f"**Benchmark Runtime**: `{run_duration:.2f}s`  ",
        "",
        "---",
        "",
        "## Executive Summary Table",
        "",
        "| Scenario | Recall | Prec | Entities | Latency | Status | Leaks / Over-redactions / Issues |",
        "|---|---:|---:|---:|---:|:---:|---|",
    ]

    for e in evaluations:
        status_badge = "✅ CLEAN" if e.is_clean else "❌ ISSUES"
        issues_list: list[str] = []
        if e.leaks:
            issues_list.append(f"**LEAK**: `{', '.join(e.leaks)}`")
        if e.over_redactions:
            issues_list.append(f"**OVER**: `{', '.join(e.over_redactions)}`")
        if e.split_entities:
            issues_list.append(f"**SPLIT**: `{', '.join(e.split_entities)}`")
        if e.integrity_issues:
            issues_list.append(f"**INTEGRITY**: `{', '.join(e.integrity_issues)}`")

        issues_summary = "<br>".join(issues_list) if issues_list else "None"
        lines.append(
            f"| `{e.name}` | {e.recall*100:.1f}% | {e.precision*100:.1f}% | {len(e.mapping)} | {e.elapsed_seconds:.2f}s | {status_badge} | {issues_summary} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## Detailed Scenario Breakdowns & Diffs",
        "",
    ])

    for i, e in enumerate(evaluations, 1):
        lines.append(f"### {i}. `{e.name}`")
        lines.append("")
        lines.append(f"- **Recall**: `{e.recall*100:.1f}%` ({len(e.leaks)} leaks / {e.expected_redactions} expected)")
        lines.append(f"- **Precision**: `{e.precision*100:.1f}%` ({len(e.over_redactions)} over-redactions / {e.expected_keeps} expected)")
        lines.append(f"- **Entities Detected**: `{len(e.mapping)}`")
        lines.append(f"- **Inference Duration**: `{e.elapsed_seconds:.3f}s`")
        if e.json_valid is not None:
            lines.append(f"- **JSON Syntax Valid**: `{'Yes' if e.json_valid else 'No'}`")
        lines.append("")

        if e.mapping:
            lines.append("#### Placeholder Vault Mapping")
            lines.append("| Placeholder | Redacted Value |")
            lines.append("|---|---|")
            for ph, val in sorted(e.mapping.items()):
                # Mask secret preview for safety in report
                preview = val if len(val) <= 20 else f"{val[:10]}...{val[-6:]}"
                lines.append(f"| `{ph}` | `{preview}` |")
            lines.append("")

        diff = generate_diff(e.source, e.sanitized)
        lines.append("#### Unified Diff (Original -> Sanitized)")
        lines.append("```diff")
        lines.append(diff if diff else " (No changes detected - document was untouched)")
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate diverse production transcripts and compare against ground truth.")
    parser.add_argument("--dir", default=str(DEFAULT_SIM_DIR), help="Directory containing production simulation files")
    parser.add_argument("--sanitized-dir", default=str(DEFAULT_SANITIZED_DIR), help="Output directory for sanitized transcripts")
    parser.add_argument("--report", default=str(DEFAULT_REPORT_MD), help="Output path for Markdown benchmark report")
    parser.add_argument("--only", default=None, help="Filter to a single scenario name")
    parser.add_argument("--profile", default="balanced", help="PII redaction profile (balanced, strict, minimal)")
    args = parser.parse_args()

    sim_dir = Path(args.dir)
    sanitized_dir = Path(args.sanitized_dir)
    sanitized_dir.mkdir(parents=True, exist_ok=True)
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    expected_files = sorted(sim_dir.glob("*.expected.json"))
    if args.only:
        expected_files = [f for f in expected_files if args.only in f.name]

    if not expected_files:
        print(f"Error: No expected.json files found in {sim_dir}", file=sys.stderr)
        return 1

    print(f"\n================================================================================")
    print(f"  PRODUCTION SIMULATION BENCHMARK: PII SANITIZATION & COMPARISON")
    print(f"================================================================================")
    print(f"  Directory:    {sim_dir}")
    print(f"  Scenarios:    {len(expected_files)}")
    print(f"  Profile:      {args.profile}")
    print(f"  Sanitized to: {sanitized_dir}")
    print(f"  Report to:    {report_path}")
    print(f"--------------------------------------------------------------------------------\n")

    print(f"Initializing PIIMiddleware (GLiNER + spaCy ensemble)...")
    init_start = time.perf_counter()
    middleware = PIIMiddleware(profile=args.profile, on_leak="warn")
    print(f"Model initialization complete in {time.perf_counter() - init_start:.2f}s.\n")

    evaluations: list[ScenarioEvaluation] = []
    bench_start = time.perf_counter()

    for idx, expected_path in enumerate(expected_files, 1):
        name = expected_path.name.removesuffix(".expected.json")
        source_path = expected_path.with_name(f"{name}.txt")
        if not source_path.is_file():
            print(f"[{idx}/{len(expected_files)}] [!] Missing source file for {name}, skipping.")
            continue

        source_text = source_path.read_text(encoding="utf-8")
        expected_data = json.loads(expected_path.read_text(encoding="utf-8"))

        print(f"[{idx:2d}/{len(expected_files):2d}] Processing {name:38} ... ", end="", flush=True)
        ev = evaluate_single_transcript(name, source_text, expected_data, middleware)
        evaluations.append(ev)

        # Write sanitized output file
        sanitized_file = sanitized_dir / f"{name}.sanitized.txt"
        sanitized_file.write_text(ev.sanitized, encoding="utf-8")

        status_str = "OK" if ev.is_clean else "ISSUES"
        print(f"{status_str:>6}  (recall={ev.recall:.2f}, prec={ev.precision:.2f}, ents={len(ev.mapping)}, {ev.elapsed_seconds:.2f}s)")
        if ev.leaks:
            print(f"         └─ LEAKS: {ev.leaks}")
        if ev.over_redactions:
            print(f"         └─ OVER-REDACTIONS: {ev.over_redactions}")
        if ev.split_entities:
            print(f"         └─ SPLIT ENTITIES: {ev.split_entities}")
        if ev.integrity_issues:
            print(f"         └─ INTEGRITY: {ev.integrity_issues}")

    total_duration = time.perf_counter() - bench_start

    print("\n" + "=" * 80)
    print(f"{'DOCUMENT':38} {'RECALL':>7} {'PREC':>7} {'ENTS':>5} {'TIME':>6}  {'STATUS'}")
    print("-" * 80)
    for ev in evaluations:
        status_str = "clean" if ev.is_clean else "FAIL"
        print(f"{ev.name:38} {ev.recall*100:6.1f}% {ev.precision*100:6.1f}% {len(ev.mapping):5d} {ev.elapsed_seconds:5.2f}s  {status_str}")

    total_docs = len(evaluations)
    macro_recall = sum(e.recall for e in evaluations) / total_docs if total_docs else 1.0
    macro_precision = sum(e.precision for e in evaluations) / total_docs if total_docs else 1.0
    total_leaks = sum(len(e.leaks) for e in evaluations)
    clean_count = sum(1 for e in evaluations if e.is_clean)

    print("-" * 80)
    print(
        f"{'MACRO BENCHMARK AVERAGE':38} {macro_recall*100:6.1f}% {macro_precision*100:6.1f}%"
        f"        leaks={total_leaks}  clean={clean_count}/{total_docs} ({total_duration:.1f}s)"
    )
    print("=" * 80 + "\n")

    # Write Markdown benchmark report
    md_content = build_markdown_report(evaluations, total_duration)
    report_path.write_text(md_content, encoding="utf-8")
    print(f"[+] Detailed Markdown scorecard and diff report written to:\n   {report_path}\n")
    print(f"[+] Sanitized transcripts written to:\n   {sanitized_dir}\n")

    return 1 if total_leaks > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
