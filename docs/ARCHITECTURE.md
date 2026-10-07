# Architecture

## Pipeline

```text
text
 |
 +-- detectWithWinkNLP()   (src/pii/wink-detector.ts)    statistical: built-in NER + (optional) POS PROPN
 |      |- Step 2: built-in wink entities -> mapWinkEntityToPIIType() (EMAIL, URL, absolute DATE, TIME)
 |      '- Step 3: (if personStrategy === 'propn') PROPN heuristic
 |
 +-- detectPersons()       (src/pii/person-detector.ts)  anchored linguistic patterns + shape validation
 |      |- Linguistic anchors: 'name-is', 'self', 'title', 'greeting', 'account', 'speaking'
 |      |- Token shape filter: isPlausibleName (rejects role words, uppercase markers, digits)
 |      '- Exact match: knownNames caller injection
 |
 +-- detectWithRegex()     (src/pii/regex-detector.ts)   deterministic rules: EMAIL, PHONE, URL, IP,
 |                                                       SSN (shape-first), CREDIT_CARD (shape+prefix),
 |                                                       ADDRESS (street/city/state/zip)
 |
 v
applyStructuralGuards()    (src/pii/structure.ts)        suppresses heuristic types (PERSON, LOC, ORG)
 |                                                       overlapping bracketed markers or line labels;
 |                                                       preserves deterministic types
 v
isTypeEnabled() filter    (src/pii/config.ts)           drops disabled categories
 |
 v
normalizeMatches()        (src/pii/normalizer.ts)        dedupe / overlap absorption / offset proof
 |
 v
maskPII() /               (src/pii/masker.ts)            right-to-left span replacement;
maskPIIWithMapping()                                     supports generic [TYPE] and numbered [TYPE_1]
 |                                                       with coreference entity map
 v
unmaskPII()               (src/pii/masker.ts)            single-pass reversible de-anonymization (maps back)
 |
 v
output_in_file()          (src/sanitizer-output.ts)      .txt sanitized output + .json audit report
```

Detection and masking are intentionally decoupled: `detectPII` never mutates text,
`maskPII` never classifies. Keep that boundary.

## Numbered Masking & Reversible Mapping (`maskPIIWithMapping`, `unmaskPII`)

To support de-anonymization and downstream workflows (e.g. LLM reasoning over pseudonymized text with subsequent re-identification):
1. **Numbered Masking (`maskPIIWithMapping`):**
   - Supports 1-based (default) or 0-based indexing per entity type (`[PERSON_1]`, `[PERSON_2]`, `[EMAIL_1]`, etc.).
   - **Entity Coreference (Default):** Identical values share the same numbered placeholder (e.g., all instances of "Sarah" receive `[PERSON_2]`), preserving conversation context.
   - **Occurrence Strategy:** Optional mode where every occurrence receives a sequentially incremented number.
   - Generates an `entityMap` (`Record<string, string>`) mapping placeholders to original plaintext.
2. **Reversible Unmasking (`unmaskPII`):**
   - Restores original plaintext from masked text in a single regex pass, preventing token collision and recursive replacement.
   - Verified 100% verbatim round-trip restoration (`unmaskPII(maskedText, entityMap) === text`).

## Person Detection Strategies (`personStrategy`)

The system supports three configurable person detection strategies:

1. **`anchored` (Default):**
   Uses `src/pii/person-detector.ts`. Extracts names anchored by conversational phrases
   (e.g., "My name is X", "Hi X", "Mr. X", "X speaking") and validates token shape.
   Yields **0 false positives** on structured/transcript text, deliberately trading recall
   on unanchored names in open prose.
2. **`propn`:**
   Legacy WinkNLP POS tagger heuristic collecting consecutive `PROPN` tokens.
   Achieves higher recall on open prose but suffers from catastrophic false positives
   (~28% precision, tagging "Agent", "System", "Monday", "Customer Support" as people).
   Retained strictly for benchmark comparison in evaluation harnesses.
3. **`off`:**
   Disables person detection entirely while keeping other sensitive identifiers active.

### Caller Injection (`knownNames`, `knownLocations`, `knownOrganizations`)
For unanchored entities (KI-005), caller applications can pass lists of known entities.
These are detected via word-boundary exact matching with high confidence (`0.99`),
allowing pipelines with contextual metadata to recover 100% precision and recall.

## Module Map — Which file do I change?

| Goal | File | Notes |
| --- | --- | --- |
| Add/adjust a deterministic pattern (SSN, card, ZIP, IBAN, address) | [src/pii/regex-detector.ts](../src/pii/regex-detector.ts) | Add a `RegexRule` to `REGEX_RULES`. Rules own their own `validator` and `score`. |
| Change anchored person detection or name validation | [src/pii/person-detector.ts](../src/pii/person-detector.ts) | Add/modify linguistic anchors in `ANCHORS` or name shape rules in `isPlausibleName()`. |
| Protect document formatting or speaker prefixes | [src/pii/structure.ts](../src/pii/structure.ts) | Adjust `getProtectedRanges()` regexes. Never apply to deterministic types. |
| Map a new wink entity type to a PII type | [src/pii/wink-detector.ts](../src/pii/wink-detector.ts) | `mapWinkEntityToPIIType()`. Only the types in the capability matrix can ever arrive here. |
| Add a new PII category | [src/pii/types.ts](../src/pii/types.ts) -> [src/pii/config.ts](../src/pii/config.ts) -> a detector | Three edits: union member, `PIIConfig` field + `isTypeEnabled` case, and an emitter. Skipping the third creates a dead toggle. |
| Change default on/off per category | [src/pii/config.ts](../src/pii/config.ts) | `DEFAULT_PII_CONFIG`. |
| Change overlap / precedence between engines | [src/pii/normalizer.ts](../src/pii/normalizer.ts) | Documented rules 1-4 in the file header. |
| Change mask format or enable numbered/reversible masking | [src/pii/masker.ts](../src/pii/masker.ts) | `maskPIIWithMapping()` / `maskPII()` (`options.numbered`, `options.numberingStrategy`), `unmaskPII()`. |
| Change what the demo runs | [src/demo.ts](../src/demo.ts) | `FILE_PATH` and the config object passed to `detectPII`. |
| Change output location / report shape | [src/sanitizer-output.ts](../src/sanitizer-output.ts) | Writes output `.txt` and JSON audit report in `sanitized_output/`. |

## Invariants — Do not break these

1. **Offset integrity.** For every returned match, `text.slice(start, end) === value`.
   Enforced in `normalizeMatches()` and re-checked in `detectWithRegex()`. Any new
   detector must satisfy it.
2. **Non-overlapping output.** `normalizeMatches()` guarantees no two returned spans
   overlap, so `maskPII` can replace right-to-left without index drift.
3. **No overlapping mask corruption.** `maskPII` sorts descending by `start`. Never
   change it to ascending.
4. **Detection is pure.** No I/O, no network, no LLM. All processing is local
   (crucial to the zero-leakage privacy guarantee of this POC).
5. **Regex engine is the authority for structured data.** `getMethodScore()` gives
   `method === 'regex'` a +0.05 tiebreak over statistical matches. Structured PII
   (card, SSN, email, phone, address) must be regex-owned, never heuristic-owned.
6. **Shape over validity.** Checksums (Luhn) and issuance rules (SSA area/group/serial)
   affect *confidence scoring*, never hard exclusion. Mistyped or fake numbers must still
   be masked.

## Tests

| File | Covers |
| --- | --- |
| [tests/pii-detector.test.ts](../tests/pii-detector.test.ts) | End-to-end `detectPII` |
| [tests/person-detector.test.ts](../tests/person-detector.test.ts) | Anchored person detection, name filters, `knownNames` |
| [tests/structure.test.ts](../tests/structure.test.ts) | Structural guards against markers/labels |
| [tests/regex-detector.test.ts](../tests/regex-detector.test.ts) | Deterministic rules, scored SSN/card, address regex |
| [tests/wink-detector.test.ts](../tests/wink-detector.test.ts) | Wink entities, absolute DATE filtering |
| [tests/normalizer.test.ts](../tests/normalizer.test.ts) | Dedupe / overlap absorption / offset proof |
| [tests/masker.test.ts](../tests/masker.test.ts) | Span replacement, custom formatters |
| [tests/output-in-file.test.ts](../tests/output-in-file.test.ts) | File + report writing |
| [tests/sample-regression.test.ts](../tests/sample-regression.test.ts) | Exact verbatim match against the expected masked output of `large_sample.txt` |
