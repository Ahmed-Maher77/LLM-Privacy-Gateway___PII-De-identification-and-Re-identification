import json
import tempfile
from types import SimpleNamespace
from pathlib import Path

import generate_report as report_module


def test_failed_candidate_is_not_written_or_advertised(monkeypatch):
    class FakeMiddleware:
        def __init__(self, **kwargs):
            pass

        def analyze(self, text):
            return SimpleNamespace(
                sanitized="UNREDACTED SECRET",
                mapping={},
                status="failed",
                profile="balanced",
                detector_status=[],
                structure={},
                roster=[],
                escapes={},
                spans=[],
                leaks=[],
                residual=[],
            )

    monkeypatch.setattr(report_module, "PIIMiddleware", FakeMiddleware)
    with tempfile.TemporaryDirectory(prefix="report-safety-", dir=Path.cwd()) as temp:
        root = Path(temp)
        source = root / "input.txt"
        report = root / "report.json"
        sanitized = root / "sanitized.txt"
        source.write_text("private input", encoding="utf-8")

        report_module.generate_report(
            source,
            report,
            "unused",
            skip_llm=True,
            sanitized_out=sanitized,
        )

        payload = json.loads(report.read_text(encoding="utf-8"))
        assert not sanitized.exists()
        assert payload["sanitized_input_file"] is None
        assert "sanitized_input_withheld" in payload
        assert "UNREDACTED SECRET" not in report.read_text(encoding="utf-8")
