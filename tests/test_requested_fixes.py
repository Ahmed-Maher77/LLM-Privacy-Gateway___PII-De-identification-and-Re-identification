from __future__ import annotations

from pii import PIIMiddleware, dedupe_placeholders, validate_output
from pii.patterns import detect_patterns
from pii.roster import rejoin_split_names
from pii.vault import find_template_literals
from pii.spans import Span


class FixedDetector:
    def __init__(self, spans: list[Span]):
        self.spans = spans

    def detect(self, text: str) -> list[Span]:
        return self.spans


def test_structural_terms_and_page_markers_are_preserved():
    text = "PROCEEDINGS\nAPPEARANCES:\nDIRECT EXAMINATION\n[Page 1]"
    start = text.index("PROCEEDINGS")
    detector = FixedDetector([
        Span(start, start + 11, "ORG", "PROCEEDINGS"),
        Span(text.index("APPEARANCES"), text.index("APPEARANCES") + 11, "ORG", "APPEARANCES"),
        Span(text.index("DIRECT EXAMINATION"), text.index("DIRECT EXAMINATION") + 18, "ORG", "DIRECT EXAMINATION"),
    ])
    result = PIIMiddleware(detectors=[detector], use_roster=False, on_leak="warn").analyze(text)
    assert result.sanitized == text
    assert find_template_literals("[Page 1]") == []
    assert "redacted-template-token-" not in result.sanitized


def test_shared_surname_honorifics_resolve_to_the_right_people():
    text = (
        "Katherine Halloran:\nhello\n"
        "Katherine Halloran:\nthanks\n"
        "Thomas Halloran:\nhello\n"
        "Thomas Halloran:\nthanks\n"
        "Ms. Katherine Halloran spoke. Mr. Thomas Halloran spoke.\n"
        "Ms. Halloran answered. Mr. Halloran objected."
    )
    result = PIIMiddleware(detectors=[], use_roster=True, on_leak="ignore").analyze(text)
    katherine = next(key for key, value in result.mapping.items() if value == "Katherine Halloran")
    thomas = next(key for key, value in result.mapping.items() if value == "Thomas Halloran")
    assert katherine != thomas
    assert result.sanitized.count(katherine) >= 2
    assert result.sanitized.count(thomas) >= 2


def test_duplicate_placeholders_are_collapsed():
    assert dedupe_placeholders("{{PERSON_1}} {{PERSON_1}} wrote") == "{{PERSON_1}} wrote"
    assert dedupe_placeholders("{{PERSON_1}}\n{{PERSON_1}} and cc'd") == "{{PERSON_1}} and cc'd"
    assert dedupe_placeholders("{{PERSON_1}}{{PERSON_1}}") == "{{PERSON_1}}"


def test_split_name_rejoin_is_conservative():
    assert rejoin_split_names("Tomoko\nYamamoto joined") == "Tomoko Yamamoto joined"
    assert rejoin_split_names("A heading:\nNext paragraph") == "A heading:\nNext paragraph"


def test_requested_categories_are_detected():
    text = (
        "Meridian & Patel LLP in Oakland on November 14, 2024 at 9:32 AM PST; "
        "Senior Data Analyst earned $147,000 for three years."
    )
    labels = {span.label for span in detect_patterns(text)}
    assert {"ORG", "LOCATION", "DATE", "TIME", "ROLE", "AMOUNT", "DURATION"} <= labels


def test_deposition_integration_keeps_structure_and_masks_job_id():
    text = (
        "PROCEEDINGS\nAPPEARANCES:\nEXAMINATION\n[Page 12]\n"
        "Job No.: 2024-1114-HALL-001\n"
        "Sarah Jenkins: hello\nSarah Jenkins: goodbye\n"
    )
    result = PIIMiddleware(detectors=[], use_roster=True, on_leak="ignore").analyze(text)
    assert "PROCEEDINGS" in result.sanitized
    assert "APPEARANCES:" in result.sanitized
    assert "EXAMINATION" in result.sanitized
    assert "[Page 12]" in result.sanitized
    assert "Job No.: {{JOB_ID_1}}" in result.sanitized
    assert "(redacted-template-token-" not in result.sanitized


def test_validate_output_preserves_structure():
    original = "PROCEEDINGS\n[Page 12]"
    assert validate_output(original, original)


def test_dry_run_reports_candidates_without_replacing_text():
    text = "09:00 - Sarah Jenkins: hello\n09:05 - Sarah Jenkins: goodbye"
    result = PIIMiddleware(detectors=[], use_roster=True, on_leak="ignore").analyze(
        text, dry_run=True
    )
    assert result.dry_run
    assert result.sanitized == text
    assert result.mapping
