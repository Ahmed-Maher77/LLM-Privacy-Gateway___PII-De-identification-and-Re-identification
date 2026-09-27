"""Apply the labels to the sampled excerpts.

The label table below was produced by reading each excerpt (see
``evaluation/gold/LABELING.md`` for who did the reading and the caveat that
attaches to it). Each row names a surface form; every word-bounded occurrence of
that form in that excerpt is labelled, longest form first so that
``Ahmed Farid`` wins over a bare ``Ahmed`` at the same position.

Rerunning this script regenerates the labelled JSONL deterministically, so the
labels live in reviewable source rather than in an opaque data file.
"""

from __future__ import annotations

import re
from pathlib import Path

from privacy_gateway.evaluation.gold import GoldDocument, GoldSet, GoldSpan

REPO = Path(__file__).resolve().parents[1]
GOLD = REPO / "evaluation" / "gold"
LABELER = "AI assistant; not human-verified"
LABELED_AT = "2026-09-27"

#: Surfaces that also appear in the shipped domain lexicon or allowlist. The
#: detectors were always going to find these, so they are marked as accepted
#: candidates rather than independent identifications.
FROM_CURATED_SOURCES = {
    "FleetCore", "CustomerDesk", "BillingPro", "OpsHub",
    "BrightPath Logistics", "Green Valley Foods", "NorthStar Systems", "Exampleco",
}

C, P, A = "certain", "probable", "ambiguous"

#: doc_id -> [(surface, entity_type, certainty), ...]
LABELS: dict[str, list[tuple[str, str, str]]] = {
    # ---------------- SME: clean, structured -------------------------------
    "sme-001": [
        ("Sarah Mitchell", "PERSON", C),
        ("BrightPath Logistics", "CUSTOMER", C),
        ("NorthStar Systems", "ORGANIZATION", C),
        ("Dubai Internet City", "LOCATION", C),
    ],
    "sme-002": [
        ("Michael Brown", "PERSON", C),
        ("Ahmed Hassan", "PERSON", C),
        ("James Anderson", "PERSON", C),
        ("FleetCore", "INTERNAL_SYSTEM", C),
        ("CustomerDesk", "INTERNAL_SYSTEM", C),
        ("https://api.fleetcore.brightpath-example.com/v2", "INTERNAL_URL", C),
    ],
    "sme-003": [
        ("Ahmed Hassan", "PERSON", C),
        ("Sarah Mitchell", "PERSON", C),
        ("Green Valley Foods", "CUSTOMER", C),
    ],
    "sme-004": [
        ("Michael Brown", "PERSON", C),
        ("Omar Khaled", "PERSON", C),
        ("Ahmed Hassan", "PERSON", C),
        ("BP-28491", "CUSTOMER_ID", C),
    ],
    "sme-005": [
        ("Sarah Mitchell", "PERSON", C),
        ("Daniel Clark", "PERSON", C),
        ("Michael Brown", "PERSON", C),
        ("OpsHub", "INTERNAL_SYSTEM", C),
        ("michael.brown@brightpath-example.com", "EMAIL", C),
        ("sarah.mitchell@brightpath-example.com", "EMAIL", C),
        ("Sarah", "PERSON", C),
    ],
    "sme-006": [
        ("Sarah Mitchell", "PERSON", C),
        ("Ahmed Hassan", "PERSON", C),
        ("Michael Brown", "PERSON", C),
        ("Emily Wilson", "PERSON", C),
        ("Robert Taylor", "PERSON", C),
        ("Omar", "PERSON", C),
        ("omar.khaled@brightpath-example.com", "EMAIL", C),
        ("robert.taylor@example.org", "EMAIL", C),
        ("+44 7700 900123", "PHONE", C),
        ("18 King Street, Manchester, M2 4AA", "ADDRESS", C),
    ],
    "sme-007": [
        ("Daniel Clark", "PERSON", C),
        ("Sarah Mitchell", "PERSON", C),
        ("Ahmed Hassan", "PERSON", C),
    ],
    "sme-008": [
        ("Daniel Clark", "PERSON", C),
        ("Sarah Mitchell", "PERSON", C),
        ("Michael Brown", "PERSON", C),
    ],
    "sme-009": [
        ("Emily Wilson", "PERSON", C),
        ("Ahmed Hassan", "PERSON", C),
        ("Daniel Clark", "PERSON", C),
        ("Sarah Mitchell", "PERSON", C),
        ("FleetCore", "INTERNAL_SYSTEM", C),
        ("OpsHub", "INTERNAL_SYSTEM", C),
        ("BP-28491", "CUSTOMER_ID", C),
    ],
    "sme-010": [
        ("Sarah Mitchell", "PERSON", C),
        ("Ahmed Hassan", "PERSON", C),
        ("Michael", "PERSON", C),
        ("sarah.mitchell@brightpath-example.com", "EMAIL", C),
        ("michael.brown@brightpath-example.com", "EMAIL", C),
    ],
    # ---------------- pod: noisy ASR ---------------------------------------
    "pod-001": [
        ("Ahmed Farid", "PERSON", C),
        ("Rania Fahmy", "PERSON", C),
        ("Ahmed Hamed", "PERSON", C),
        # Rendered with a stray article by the transcriber, but they are names.
        ("Shalaby", "PERSON", P),
        ("Abdulrahman", "PERSON", P),
        ("Badri", "PERSON", P),
    ],
    "pod-002": [
        ("Ahmed Hamed", "PERSON", C),
        ("Ahmed Maher", "PERSON", C),
        ("Ahmed Farid", "PERSON", C),
        ("Hossam Badri", "PERSON", C),
        ("Michael Ibrahim", "PERSON", C),
        ("Michael", "PERSON", P),
        ("Hamed", "PERSON", P),
        # A name or the Arabic word; unresolvable from this context.
        ("Rama", "PERSON", A),
        # "Cortana" is a product, not a person. The prototype labelled it PER
        # and corrupted it into <PER_11>rtana.
    ],
    "pod-003": [
        ("Ahmed Farid", "PERSON", C),
        ("Ahmed Hamed", "PERSON", C),
        ("Lamia Aly", "PERSON", C),
        ("Hossam Badri", "PERSON", C),
        ("Hossam", "PERSON", C),
        ("Ahmed", "PERSON", C),
        ("Ish", "PERSON", A),
    ],
    "pod-004": [
        ("Hossam Badri", "PERSON", C),
        ("Ahmed Farid", "PERSON", C),
        ("Ahmed Hamed", "PERSON", C),
        ("Rania Fahmy", "PERSON", C),
        ("Ahmed", "PERSON", C),
        ("Mike", "PERSON", P),
        ("Lamya", "PERSON", P),
        ("Nish", "PERSON", A),
        ("Kol", "PERSON", A),
    ],
    "pod-005": [
        ("Lamia Aly", "PERSON", C),
        ("Ahmed Farid", "PERSON", C),
        ("Ahmed Hamed", "PERSON", C),
        ("Ahmed Maher", "PERSON", C),
        ("Badri Mohamed", "PERSON", P),
        ("Lamya", "PERSON", P),
        ("Noha", "PERSON", P),
        ("Mark", "PERSON", A),
    ],
    "pod-006": [
        ("Lamia Aly", "PERSON", C),
        ("Ahmed Farid", "PERSON", C),
        ("Ahmed Hamed", "PERSON", C),
        ("Yani", "PERSON", A),
    ],
    "pod-007": [
        ("Lamia Aly", "PERSON", C),
        ("Ahmed Farid", "PERSON", C),
        ("Tom Galal", "PERSON", C),
        ("Nabeeh", "PERSON", P),
        ("Mike", "PERSON", P),
    ],
    "pod-008": [
        ("Lamia Aly", "PERSON", C),
        ("Ahmed Farid", "PERSON", C),
        ("Hossam Badri", "PERSON", C),
        ("Adel", "PERSON", P),
        ("Aly", "PERSON", P),
        ("New Zealand", "LOCATION", C),
        ("Vadushal Ali", "PERSON", A),
        ("Kirsaryani", "PERSON", A),
        ("Mish", "PERSON", A),
        # "GitHub" is a public product and is not labelled.
    ],
    "pod-009": [
        ("Ahmed Farid", "PERSON", C),
        ("Lamia Aly", "PERSON", C),
        ("Hossam Badri", "PERSON", C),
        ("Mosad", "PERSON", A),
    ],
    "pod-010": [
        ("Hossam Badri", "PERSON", C),
        ("Lamia Aly", "PERSON", C),
        ("Ahmed Hamed", "PERSON", C),
        ("Noha", "PERSON", P),
    ],
    "pod-011": [
        ("Ahmed Farid", "PERSON", C),
        ("Lamia Aly", "PERSON", C),
        ("Hossam Badri", "PERSON", C),
    ],
    "pod-012": [
        ("Lamia Aly", "PERSON", C),
        ("Ahmed Farid", "PERSON", C),
        ("Ahmed Hamed", "PERSON", C),
        ("Ahmed", "PERSON", C),
        ("Fathy", "PERSON", P),
        ("Ravi", "PERSON", P),
        ("America", "LOCATION", C),
    ],
}


def label_document(doc: GoldDocument) -> GoldDocument:
    rows = LABELS.get(doc.doc_id, [])
    # Longest surface first, so "Ahmed Farid" claims the span before "Ahmed".
    rows = sorted(rows, key=lambda r: -len(r[0]))
    taken: list[tuple[int, int]] = []
    spans: list[GoldSpan] = []

    for surface, entity_type, certainty in rows:
        for match in re.finditer(r"(?<!\w)" + re.escape(surface) + r"(?!\w)", doc.text):
            start, end = match.span()
            if any(s < end and start < e for s, e in taken):
                continue
            taken.append((start, end))
            spans.append(
                GoldSpan(
                    start=start,
                    end=end,
                    entity_type=entity_type,
                    text=doc.text[start:end],
                    provenance=(
                        "accepted_candidate"
                        if surface in FROM_CURATED_SOURCES
                        else "independent"
                    ),
                    certainty=certainty,
                )
            )

    spans.sort(key=lambda s: s.start)
    return GoldDocument(
        doc_id=doc.doc_id,
        text=doc.text,
        entities=tuple(spans),
        source_file=doc.source_file,
        source_sha256=doc.source_sha256,
        source_char_start=doc.source_char_start,
        source_char_end=doc.source_char_end,
        labeler=LABELER,
        labeled_at=LABELED_AT,
        guideline_version="1.0",
        split=doc.split,
    )


def main() -> int:
    total = 0
    for stem in ("pod_meeting", "sme_meeting_transcript"):
        source = GOLD / f"{stem}.unlabelled.jsonl"
        gold = GoldSet.load(source)
        labelled = GoldSet(tuple(label_document(d) for d in gold))
        problems = labelled.validate()
        if problems:
            for problem in problems:
                print(f"  INVALID: {problem}")
            return 1
        path = labelled.save(GOLD / f"{stem}.v1.jsonl")
        count = sum(len(d.entities) for d in labelled)
        total += count
        print(f"{len(labelled)} documents, {count} spans -> {path}")
    print(f"total spans: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
