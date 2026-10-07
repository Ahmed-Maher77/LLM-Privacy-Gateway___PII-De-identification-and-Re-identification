"""Run the full PII workflow over a file and write a redacted JSON report."""

from __future__ import annotations

import argparse
import json
import sys
import time
import warnings
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from dotenv import load_dotenv

from pii import PIIMiddleware
from pii.errors import EXIT_LEAK, EXIT_OK, EXIT_REVIEW, EXIT_USAGE, PIIError
from pii.policy import DEFAULT_PROFILE
from pii.reporting import (
    WARNING_TEXT,
    make_salt,
    summarize_findings,
    summarize_leaks,
    summarize_mapping,
    write_text,
)
from pii.residual import explain, severity_counts

DEFAULT_SANITIZED_DIR = Path("reports/sanitized")


@dataclass(frozen=True, slots=True)
class ReportOutcome:
    path: Path
    status: str
    exit_code: int
    findings: int


def generate_report(
    input_path: Path,
    report_path: Path,
    model_name: str,
    *,
    profile: str = DEFAULT_PROFILE,
    entities: Mapping[str, bool] | None = None,
    fixed_names: Sequence[str] = (),
    skip_llm: bool = False,
    on_leak: str = "raise",
    strict: bool = False,
    include_secrets: bool = False,
    explain_findings: bool = False,
    sanitized_out: Path | None = None,
) -> ReportOutcome:
    input_text = input_path.read_text(encoding="utf-8")
    # "warn" so the artefact still gets written for triage; the exit code and
    # the LLM gate below are what actually enforce the policy.
    middleware = PIIMiddleware(
        profile=profile,
        entities=entities,
        fixed_names=fixed_names,
        on_leak="warn",
        strict=strict,
    )

    start_total = time.perf_counter()
    start_anonymize = time.perf_counter()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        analysis = middleware.analyze(input_text)
    anonymization_seconds = time.perf_counter() - start_anonymize

    # Default out of test_data/, which holds local working copies of inputs.
    #
    # Failed and review results may still contain PII. Never persist their
    # candidate output as a sanitized side-file; the JSON report records that
    # it was withheld instead.
    sanitized_path = sanitized_out or DEFAULT_SANITIZED_DIR / f"{input_path.stem}.txt"

    result = ""
    result_sanitized = ""
    llm_seconds = 0.0
    restoration_seconds = 0.0
    llm_skipped = None

    if analysis.status == "clean":
        write_text(sanitized_path, analysis.sanitized, contains_secrets=False)

    if skip_llm:
        llm_skipped = "--skip-llm"
    elif analysis.status != "clean":
        # Fail-closed means do not transmit. Exiting non-zero after sending
        # the data to a third party is not a control, it is a postmortem.
        llm_skipped = f"verification status={analysis.status}"
    else:
        from langchain_ollama import ChatOllama

        llm = ChatOllama(model=model_name, temperature=0)
        start_llm = time.perf_counter()
        response = llm.invoke(analysis.sanitized)
        llm_seconds = time.perf_counter() - start_llm

        result_sanitized = response.content
        start_restore = time.perf_counter()
        result = middleware.restore_for(response.content, analysis)
        restoration_seconds = time.perf_counter() - start_restore

    salt = make_salt()
    report: dict = {
        "contains_secrets": include_secrets,
        "status": analysis.status,
        "created_at": datetime.now(UTC).isoformat(),
        "input_file": str(input_path),
        "sanitized_input_file": str(sanitized_path) if analysis.status == "clean" else None,
        "profile": analysis.profile,
        "detectors": analysis.detector_status,
        "structure": analysis.structure,
        "mapping_summary": summarize_mapping(analysis, reveal=include_secrets, salt=salt),
        "roster_count": len(analysis.roster),
        "escaped_placeholder_literals": len(analysis.escapes),
        "span_count": len(analysis.spans),
        "llm_skipped": llm_skipped,
        # The pre-restoration response is safe by construction and is what you
        # actually debug with; the restored text carries every real value.
        "result_sanitized": result_sanitized,
        "verification": {
            "status": analysis.status,
            "detected_leaks": summarize_leaks(
                analysis.leaks, reveal=include_secrets, salt=salt
            ),
            "residual": {
                "counts": severity_counts(analysis.residual),
                "items": summarize_findings(
                    analysis.residual, reveal=include_secrets, salt=salt
                ),
            },
        },
        "performance": {
            "anonymization_seconds": anonymization_seconds,
            "llm_seconds": llm_seconds,
            "restoration_seconds": restoration_seconds,
            "total_seconds": time.perf_counter() - start_total,
        },
    }

    if include_secrets:
        report = {"warning": WARNING_TEXT, **report}
        report["mapping"] = analysis.mapping
        report["roster"] = analysis.roster
        report["result"] = result

    if analysis.status == "clean":
        report["sanitized_input"] = analysis.sanitized
    else:
        # When verification failed the sanitized text still contains secrets by
        # definition. Embedding it would make the report the delivery vehicle
        # for the leak it is reporting.
        report["sanitized_input_withheld"] = f"verification status={analysis.status}"

    write_text(
        report_path,
        json.dumps(report, indent=2, ensure_ascii=True),
        contains_secrets=include_secrets,
    )

    if analysis.status == "clean":
        print(f"Sanitized input saved to {sanitized_path}")
    else:
        print(f"Sanitized input withheld (verification status={analysis.status})")
    print(f"Entities: {len(analysis.mapping)} | status: {analysis.status}")
    if llm_skipped:
        print(f"LLM not called ({llm_skipped})")
    if explain_findings and analysis.residual:
        print(explain(analysis.residual))

    exit_code = EXIT_OK
    if analysis.status == "failed":
        exit_code = EXIT_LEAK
    elif analysis.status == "review" and strict:
        exit_code = EXIT_REVIEW

    return ReportOutcome(
        path=report_path,
        status=analysis.status,
        exit_code=exit_code,
        findings=len(analysis.residual),
    )


def parse_entity_override(raw: str) -> tuple[str, bool]:
    """Parse "KEY=true"/"KEY=false" for --entity.

    Key validation is left to ``PIIMiddleware`` itself, so a typo raises the
    same error and lists the same candidates whether it came from a CLI flag
    or a Python caller.
    """
    key, sep, value = raw.partition("=")
    normalized = value.strip().casefold()
    if not sep or normalized not in {"true", "false"}:
        raise argparse.ArgumentTypeError(f"expected KEY=true|false, got {raw!r}")
    return key.strip(), normalized == "true"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a PII workflow report.",
        epilog="Exit codes: 0 clean, 2 usage, 3 leak detected, 4 review required, 5 detector missing.",
    )
    parser.add_argument("input_file", type=Path)
    # Per-input by default: a single rolling "latest_run.json" meant each run
    # destroyed the previous audit trail.
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--model", default="gpt-oss:120b-cloud")
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument(
        "--entity",
        action="append",
        type=parse_entity_override,
        default=[],
        dest="entities",
        metavar="KEY=true|false",
        help="Override one entity type's redaction, independent of --profile "
        "(repeatable), e.g. --entity duration=true --entity url=false.",
    )
    parser.add_argument(
        "--fixed-name",
        action="append",
        default=[],
        dest="fixed_names",
        metavar="NAME",
        help="Mask this name wherever it appears, independent of detection "
        "(repeatable).",
    )
    parser.add_argument("--sanitized-out", type=Path, default=None)
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Anonymize and verify only, without calling the LLM.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat medium-confidence residual findings as a failure.",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Print every residual finding, including suppressed ones.",
    )
    parser.add_argument(
        "--include-secrets",
        action="store_true",
        help="Write real PII into the report. The file must not be committed.",
    )
    args = parser.parse_args()

    if not args.input_file.is_file():
        parser.error(f"no such file: {args.input_file}")

    report_path = args.report or Path("reports") / f"{args.input_file.stem}_run.json"

    if args.include_secrets:
        print(f"WARNING: --include-secrets writes real PII to {report_path}.", file=sys.stderr)
        print(f"WARNING: {WARNING_TEXT}", file=sys.stderr)

    load_dotenv()
    try:
        outcome = generate_report(
            args.input_file,
            report_path,
            args.model,
            profile=args.profile,
            entities=dict(args.entities),
            fixed_names=args.fixed_names,
            skip_llm=args.skip_llm,
            strict=args.strict,
            include_secrets=args.include_secrets,
            explain_findings=args.explain,
            sanitized_out=args.sanitized_out,
        )
    except PIIError as exc:
        print(str(exc), file=sys.stderr)
        return exc.exit_code
    except ValueError as exc:
        # An unrecognised --entity key, or a blank --fixed-name: a
        # construction-time mistake in the caller's own input, not a
        # detection-time PIIError, but still a usage error, not a crash.
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE

    print(f"Report saved to {outcome.path}  [status={outcome.status}]")
    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
