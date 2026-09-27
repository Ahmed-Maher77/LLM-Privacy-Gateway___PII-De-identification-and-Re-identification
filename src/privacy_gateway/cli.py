"""Command line interface.

``sanitize`` runs everything except the model call, which is the useful mode
for inspecting what the gateway would send. ``run`` adds the model.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import Settings
from .errors import GatewayError
from .gateway import GatewayRequest, PrivacyGateway, new_conversation_id
from .llm.base import build_llm
from .report import build_report, write_report


def _read(path: Path) -> str:
    # Read bytes and decode explicitly so CRLF survives into normalization
    # rather than being silently translated by universal newlines.
    return path.read_bytes().decode("utf-8")


def _artifact_path(settings: Settings, input_path: Path) -> Path:
    # Never written next to the source: the prototype put its sanitized output
    # into test_data/, where it was committed alongside the inputs.
    return settings.artifacts_dir / f"{input_path.stem}__sanitized{input_path.suffix}"


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input_file", type=Path)
    parser.add_argument("--conversation-id", default=None)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument(
        "--include-content",
        action="store_true",
        help="embed the sanitized input and the answer in the report (they contain placeholders, and the answer contains restored values)",
    )
    parser.add_argument(
        "--include-mapping",
        action="store_true",
        help="embed the placeholder mapping in the report. THIS IS THE SECRET.",
    )
    parser.add_argument("--fail-mode", choices=("closed", "open"), default=None)
    parser.add_argument("--detectors", default=None, help="comma-separated detector names")


def _settings(args: argparse.Namespace) -> Settings:
    settings = Settings.from_env()
    overrides = {}
    if args.fail_mode:
        overrides["fail_mode"] = args.fail_mode
    if args.detectors:
        from dataclasses import replace

        enabled = tuple(d.strip() for d in args.detectors.split(",") if d.strip())
        overrides["detectors"] = replace(settings.detectors, enabled=enabled)
    return settings.with_overrides(**overrides) if overrides else settings


def _emit(args, settings, result, input_path, sanitized_path) -> None:
    report = build_report(
        result,
        settings,
        input_path=input_path,
        sanitized_path=sanitized_path,
        include_content=args.include_content,
        include_mapping=args.include_mapping,
    )
    if args.report:
        write_report(report, args.report)
        print(f"Report written to {args.report}")
    else:
        print(json.dumps(report, indent=2, ensure_ascii=True))


def cmd_sanitize(args: argparse.Namespace) -> int:
    settings = _settings(args)
    gateway = PrivacyGateway(settings)
    text = _read(args.input_file)
    conversation_id = args.conversation_id or new_conversation_id()
    outcome = gateway.sanitize(GatewayRequest(text=text, conversation_id=conversation_id))

    sanitized_path = _artifact_path(settings, args.input_file)
    sanitized_path.parent.mkdir(parents=True, exist_ok=True)
    sanitized_path.write_text(outcome.sanitized_text, encoding="utf-8")
    print(f"Sanitized input written to {sanitized_path}")
    print(f"{len(outcome.entities)} entities, {len(outcome.store)} mapping entries")

    from .gateway import GatewayResult
    from .observability.timing import Timings

    result = GatewayResult(
        status="ok", output="", sanitize=outcome, timings=Timings()
    )
    _emit(args, settings, result, args.input_file, sanitized_path)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    settings = _settings(args)
    llm = build_llm(settings.llm)
    gateway = PrivacyGateway(settings, llm=llm)
    text = _read(args.input_file)
    conversation_id = args.conversation_id or new_conversation_id()

    result = gateway.run(
        GatewayRequest(
            text=text, conversation_id=conversation_id, instruction=args.instruction
        )
    )

    sanitized_path = _artifact_path(settings, args.input_file)
    sanitized_path.parent.mkdir(parents=True, exist_ok=True)
    sanitized_path.write_text(result.sanitized_input, encoding="utf-8")

    print(f"Status: {result.status}")
    for warning in result.warnings:
        print(f"  warning: {warning}")
    print(f"Sanitized input written to {sanitized_path}")
    _emit(args, settings, result, args.input_file, sanitized_path)

    if args.print_answer:
        print("\n--- answer ---\n")
        print(result.output)
    return 0 if result.status != "blocked" else 6


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="privacy-gateway",
        description="Sensitive-data detection, de-identification and re-identification gateway.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sanitize = sub.add_parser("sanitize", help="detect and pseudonymize; no model call")
    _add_common(sanitize)
    sanitize.set_defaults(func=cmd_sanitize)

    run = sub.add_parser("run", help="full pipeline including the model call")
    _add_common(run)
    run.add_argument("--instruction", default=None)
    run.add_argument("--print-answer", action="store_true")
    run.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except GatewayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
