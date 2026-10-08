"""Run every implementation on the same document and compare the results.

    python benchmark/run.py [--runs N] [--only 01,03]

Each implementation runs in its own environment (its .venv or node_modules), so
install each one first as its README describes. Results go to
benchmark/results/: one JSON file per implementation and summary.md.

What is measured, on benchmark/sample.txt against benchmark/labels.json:
- leaked: labelled values that still appear verbatim in the output;
- partial: multi-word names not leaked whole, but with a word of 3+ letters
  still visible;
- over-redacted: ordinary terms from the "keep" list that no longer appear;
- cold start: process start to first result, including model loading;
- warm: median time per document over the following runs;
- memory: resident set size after the runs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
WINDOWS = os.name == "nt"
FULL_NAME_RE = re.compile(r"[^\W\d_][\w'-]+(?: [^\W\d_][\w'-]+)+")

IMPLEMENTATIONS = {
    "01": ("01-python-gliner-spacy-gateway", "python"),
    "02": ("02-ts-lists-transformersjs-ner", "node"),
    "03": ("03-ts-winknlp-regex-rules-poc", "node"),
    "04": ("04-ts-multilayer-lists-regex-ner-winknlp", "node"),
    "05": ("05-python-presidio-bert-qwen-gateway", "python"),
    "06": ("06-ts-winknlp-lite", "node"),
}


def command(key: str, folder: Path, kind: str, output: Path, runs: int) -> list[str]:
    if kind == "python":
        python = folder / ".venv" / ("Scripts/python.exe" if WINDOWS else "bin/python")
        return [str(python), str(HERE / "adapters" / f"{key}.py"), str(HERE / "sample.txt"), str(output), str(runs)]
    tsx = folder / "node_modules" / ".bin" / ("tsx.cmd" if WINDOWS else "tsx")
    return [str(tsx), str(HERE / "adapters" / f"{key}.ts"), str(HERE / "sample.txt"), str(output), str(runs)]


def score(sanitized: str, labels: dict) -> dict:
    leaked = {
        category: [value for value in values if value in sanitized]
        for category, values in labels["pii"].items()
    }
    partial = []
    for value in labels["pii"]["PERSON"]:
        # Only full names ("First Last"), not greeting or honorific mentions.
        if value in sanitized or not FULL_NAME_RE.fullmatch(value) or value.startswith("Hi "):
            continue
        words = [w for w in re.split(r"[\s-]+", value) if len(w) >= 3]
        if any(re.search(rf"(?<!\w){re.escape(w)}(?!\w)", sanitized) for w in words):
            partial.append(value)
    lost = [term for term in labels["keep"] if term not in sanitized]
    return {"leaked": leaked, "partial": partial, "over_redacted": lost}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=5, help="warm runs after the first call (default 5)")
    parser.add_argument("--only", default="", help="comma-separated keys, e.g. 01,03")
    args = parser.parse_args()

    labels = json.loads((HERE / "labels.json").read_text(encoding="utf-8"))
    total = sum(len(values) for values in labels["pii"].values())
    results_dir = HERE / "results"
    results_dir.mkdir(exist_ok=True)
    keys = [k.strip() for k in args.only.split(",") if k.strip()] or list(IMPLEMENTATIONS)

    rows = []
    for key in keys:
        name, kind = IMPLEMENTATIONS[key]
        folder = ROOT / name
        output = results_dir / f"{name}.json"
        print(f"running {name} ...", flush=True)
        proc = subprocess.run(
            command(key, folder, kind, output, args.runs),
            cwd=folder, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if proc.returncode != 0 or not output.exists():
            print(f"  failed (exit {proc.returncode}):\n{proc.stderr[-2000:]}", file=sys.stderr)
            rows.append({"name": name, "error": f"exit {proc.returncode}"})
            continue
        result = json.loads(output.read_text(encoding="utf-8"))
        result.update(score(result["sanitized"], labels))
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        rows.append(result)

    lines = [
        "| Implementation | Protected | Leaked values | Partial names | Over-redacted | Cold start | Warm / doc | Memory |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        if "error" in row:
            lines.append(f"| `{row['name']}` | failed ({row['error']}) | | | | | | |")
            continue
        leaked = [f"{v} ({c})" for c, values in row["leaked"].items() for v in values]
        n_leaked = len(leaked)
        warm = statistics.median(row["warm_s"]) if row["warm_s"] else row["cold_s"]
        memory = f"{row['rss_mb']:.0f} MB" if row["rss_mb"] else "n/a"
        lines.append(
            f"| `{row['name']}` | {total - n_leaked}/{total} | {n_leaked} | {len(row['partial'])} | "
            f"{len(row['over_redacted'])} | {row['cold_s']:.1f} s | {warm * 1000:.0f} ms | {memory} |"
        )
    summary = "\n".join(lines) + "\n"
    (results_dir / "summary.md").write_text(summary, encoding="utf-8")
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
