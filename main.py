"""End-to-end example: anonymize a transcript, call the LLM, restore the PII."""

from __future__ import annotations

import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from langchain_ollama import ChatOllama

from pii import PIIMiddleware
from pii.errors import EXIT_OK, PIIError
from pii.residual import explain

load_dotenv()

INPUT_FILE = Path("test_data/sme_meeting_transcript.txt")
MODEL = "gpt-oss:120b-cloud"

llm = ChatOllama(model=MODEL, temperature=0)

# on_leak="raise" is the default: analyze() refuses to return a result that
# still contains PII, so the llm.invoke() below is unreachable on a failure.
# Enforcement lives in one place rather than in every caller.
middleware = PIIMiddleware()


def secure_llm_call(user_input: str) -> str:
    # ============ 1. Detect + pseudonymize + verify ============
    start = time.perf_counter()
    result = middleware.analyze(user_input)
    print(f"Anonymization took {time.perf_counter() - start:.2f} seconds")

    print(f"Profile: {result.profile}")
    print(f"Speakers detected: {', '.join(result.roster) or 'none'}")
    print(f"Entities replaced: {len(result.mapping)}")
    if result.escapes:
        print(f"Neutralized placeholder literals in input: {len(result.escapes)}")
    print(f"Verification: {result.status}")
    if result.residual:
        print(explain(result.residual))

    # ============ 2. Send ONLY sanitized data to the LLM ============
    start = time.perf_counter()
    response = llm.invoke(result.sanitized)
    print(f"LLM call took {time.perf_counter() - start:.2f} seconds")

    # ============ 3. Restore original values ============
    start = time.perf_counter()
    # restore_for cannot be called without the escape table, unlike restore().
    final_response = middleware.restore_for(response.content, result)
    print(f"Restoration took {time.perf_counter() - start:.4f} seconds")

    return final_response


def main() -> int:
    try:
        print(secure_llm_call(INPUT_FILE.read_text(encoding="utf-8")))
    except PIIError as exc:
        print(f"Refusing to continue: {exc}", file=sys.stderr)
        return exc.exit_code
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
