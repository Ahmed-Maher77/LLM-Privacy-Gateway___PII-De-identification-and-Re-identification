import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from dotenv import load_dotenv
from langchain_ollama import ChatOllama

from reduct_and_restore_PII import PIIMiddleware


def generate_report(input_path: Path, report_path: Path, model_name: str) -> Path:
    input_text = input_path.read_text(encoding="utf-8")
    middleware = PIIMiddleware()

    start_total = time.perf_counter()
    start_anonymize = time.perf_counter()
    sanitized_input, mapping = middleware.anonymize(input_text)
    anonymization_seconds = time.perf_counter() - start_anonymize
    sanitized_input_path = input_path.with_name(
        f"{input_path.stem}__sanitized-input{input_path.suffix}"
    )
    sanitized_input_path.write_text(sanitized_input, encoding="utf-8")

    llm = ChatOllama(model=model_name, temperature=0)
    start_llm = time.perf_counter()
    response = llm.invoke(sanitized_input)
    llm_seconds = time.perf_counter() - start_llm

    start_restore = time.perf_counter()
    result = middleware.restore(response.content, mapping)
    restoration_seconds = time.perf_counter() - start_restore

    report = {
        "created_at": datetime.now(UTC).isoformat(),
        "input_file": str(input_path),
        "sanitized_input_file": str(sanitized_input_path),
        "result": result,
        "sanitized_input": sanitized_input,
        "entity_count": len(mapping),
        "performance": {
            "anonymization_seconds": anonymization_seconds,
            "llm_seconds": llm_seconds,
            "restoration_seconds": restoration_seconds,
            "total_seconds": time.perf_counter() - start_total,
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    print(f"Sanitized input saved to {sanitized_input_path}")
    return report_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a PII workflow report.")
    parser.add_argument("input_file", type=Path)
    parser.add_argument("--report", type=Path, default=Path("reports/latest_run.json"))
    parser.add_argument("--model", default="gpt-oss:120b-cloud")
    args = parser.parse_args()

    load_dotenv()
    report_path = generate_report(args.input_file, args.report, args.model)
    print(f"Report saved to {report_path}")


if __name__ == "__main__":
    main()
