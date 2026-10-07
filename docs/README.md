# Documentation Index — read this first

This folder exists so you do **not** have to read every file in `src/` to understand
how detection behaves or why an output looks wrong. Start here.

| Read this | When |
| --- | --- |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | You need the pipeline, the module map, and "which file do I change for X". |
| [WINKNLP-CAPABILITIES.md](./WINKNLP-CAPABILITIES.md) | You are about to assume WinkNLP detects something. Check the matrix before writing code. |
| [KNOWN-ISSUES.md](./KNOWN-ISSUES.md) | Output looks wrong. Every known defect is registered here with evidence and root cause. |

## 30-second summary of the current state

The pipeline combines **WinkNLP** with **deterministic regex and anchored linguistic rules**, merged by a span normalizer and masked with reversible coreference-aware pseudonymization.

- [KI-001](./KNOWN-ISSUES.md#ki-001) through [KI-008](./KNOWN-ISSUES.md#ki-008) are resolved, except [KI-005](./KNOWN-ISSUES.md#ki-005) (WinkNLP package limitation, open).
- **Person detection** uses conversational linguistic anchors + shape validation (`person-detector.ts`), yielding **100% precision with 0 false positives** on the reference transcript. Legacy PROPN POS heuristic remains configurable.
- **SSN, Credit Card, and Address** are fully masked via deterministic rules (shape-first with scored validity), preventing PII disclosure leaks ([KI-002](./KNOWN-ISSUES.md#ki-002), [KI-003](./KNOWN-ISSUES.md#ki-003), [KI-004](./KNOWN-ISSUES.md#ki-004)).
- **Document structure is preserved**: structural guards protect headers, speaker prefixes, and bracketed markers ([KI-006](./KNOWN-ISSUES.md#ki-006)).
- **All 60 unit and regression tests pass** across 9 suites.

## Reproduce the reference run

```bash
npm run demo      # reads samples/large_sample.txt -> sanitized_output/
npm test
npm run evaluate  # precision / recall / F1
```

Reference input/output pair:
`samples/large_sample.txt` -> `sanitized_output/sanitized_output.txt`
(+ `sanitized_output/sanitized_output_report.json` for per-match offsets).
