# Known issues — defect register

Reference run: `samples/large_sample.txt` -> `sanitized_output/sanitized_output.txt`
(15 matches; per-match offsets in `sanitized_output/sanitized_output_report.json`).

Headline on current run: **15 spans masked, exactly 15 real PII entities (100% precision, 0 false positives).**
All real PII leaks (SSN, credit card, full address) are resolved, and document structure is preserved intact.

| ID | Status | Severity | Defect | Cause | Resolution / Notes |
| --- | --- | --- | --- | --- | --- |
| [KI-001](#ki-001) | **Resolved** | High | 23 false `[PERSON]` tags | our code | Replaced POS PROPN heuristic with anchored detection (`person-detector.ts`) and shape validation. |
| [KI-002](#ki-002) | **Resolved** | **Critical** | SSN not masked (`000-12-3456`) | our code | Removed SSA issuance hard gate. Shape-first regex with scored validity (0.98 vs 0.90). |
| [KI-003](#ki-003) | **Resolved** | **Critical** | Credit card not masked (`4111 2222 3333 4321`) | our code | Replaced strict Luhn hard gate with shape + brand prefix check; Luhn used for scoring. Added `strictLuhn` option. |
| [KI-004](#ki-004) | **Resolved** | Medium | `address`/`location`/`organization` dead toggles | our code | Implemented `ADDRESS` regex detector; set `location`/`organization` to `false` by default with `knownLocations`/`knownOrganizations` emitters. |
| [KI-005](#ki-005) | **Open** | Medium | No real name/org/location NER available | **package limit** | `wink-eng-lite-web-model` lacks NER classes. Unanchored names in open prose require caller-supplied `knownNames` or transformer NER. |
| [KI-006](#ki-006) | **Resolved** | Low | Document structure masked (headers, markers, speaker labels) | our code | Implemented structural guards (`structure.ts`) protecting bracketed markers and line-leading labels from heuristic masking. |
| [KI-007](#ki-007) | **Resolved** | Low | `today` masked as `[DATE]` | config/code | Narrowed `DATE` detector to require digits (`/\d/`), leaving relative time expressions unmasked while preserving absolute dates. |
| [KI-008](#ki-008) | **Resolved** | Low | Stale compiled `.js` beside `.ts` sources | housekeeping | Deleted all stale `.js` files in `src/pii/`; configured `.gitignore` to prevent re-occurrence. |
| [KI-009](#ki-009) | **Documented** | Low | Non-Latin / ASCII-only Name Limitation | architectural | Person detector anchor regexes assume Latin script. Multilingual non-Latin names (e.g. Arabic) require caller `knownNames`. |

---

## KI-001 [RESOLVED]

### 23 of 29 `[PERSON]` tags were false positives

**Resolution:**
1. Created `src/pii/person-detector.ts` implementing 6 linguistic anchors (`name-is`, `self`, `title`, `greeting`, `account`, `speaking`).
2. Implemented strict shape validation (`isPlausibleName`) rejecting all-caps markers, single-character invalid tokens, digits, and system role words (`Agent`, `System`, `Customer`, etc.).
3. Introduced `personStrategy: 'off' | 'anchored' | 'propn'` (default `'anchored'`).
4. Deleted the static `NON_PERSON_WORDS` denylist from `wink-detector.ts`.
5. Supported caller-supplied `knownNames: string[]` for exact-match detection.

**Outcome:**
`samples/large_sample.txt` now detects 6 PERSON entities with **0 false positives** (100% precision, down from 23 false positives).

---

## KI-002 [RESOLVED]

### SSN `000-12-3456` was not masked (real PII leak)

**Resolution:**
1. Replaced the SSA issuance lookahead regex with a pure shape matcher: `/\b\d{3}-\d{2}-\d{4}\b/g`.
2. Added `isIssuableSSN` helper to assign confidence:
   - Issuable numbers: `0.98`
   - Non-issuable numbers (e.g. area `000`, `666`, `9xx`): `0.90` (still fully masked).
3. Rewrote test assertions in `tests/regex-detector.test.ts` to enforce shape-first masking.

**Outcome:**
`000-12-3456` is successfully detected and masked as `[SSN]`.

---

## KI-003 [RESOLVED]

### Credit card `4111 2222 3333 4321` was not masked (real PII leak)

**Resolution:**
1. Replaced the strict Luhn validator hard gate with `hasCardBrandPrefix(digits)`:
   - Checks IIN prefixes: Visa (`4`), MasterCard (`51-55`, `2221-2720`), Amex (`34`, `37`), Discover (`6011`, `65`, `644-649`), Diners, JCB.
   - Accepts separated numbers with valid brand prefix even if Luhn fails (scoring `0.85`).
   - Luhn-valid numbers score `0.98`.
2. Added `strictLuhn?: boolean` option to `RegexDetectorOptions` and `PIIConfig` for backwards compatibility/evaluation.

**Outcome:**
`4111 2222 3333 4321` is successfully detected and masked as `[CREDIT_CARD]`.

---

## KI-004 [RESOLVED]

### `address`, `location`, `organization` were dead config toggles

**Resolution:**
1. Implemented a deterministic `ADDRESS` regex detector (`ADDRESS_PATTERN`) covering street suffix, city, state, and ZIP.
2. Updated `DEFAULT_PII_CONFIG` so `location: false` and `organization: false` by default.
3. Added `knownLocations` and `knownOrganizations` to config, wiring them to exact-match detectors so the toggles correspond to real emitters.

**Outcome:**
`742 Evergreen Terrace, Springfield, OR 97403` is cleanly detected as a single unified `[ADDRESS]` span.

---

## KI-005 [OPEN — PACKAGE LIMITATION]

### No person / organization / location NER in WinkNLP

**Details:**
`wink-eng-lite-web-model` provides tokenization, POS tagging, and limited rule-based entities (email, url, date, time), but does **not** include an NER model trained for `PERSON`, `ORGANIZATION`, or `LOCATION`.

**Impact:**
- Unanchored names in open prose (e.g., "Barack Obama visited London", "Ahmed contacted Ahmed") cannot be detected without linguistic context or caller-provided lists.
- If open-prose recall is required, the solution is to supply `knownNames` from application context, or pair WinkNLP with a dedicated local ONNX NER model (e.g. `Xenova/bert-base-NER`).

---

## KI-006 [RESOLVED]

### Masking destroyed document structure

**Resolution:**
1. Implemented `src/pii/structure.ts` with `getProtectedRanges()` and `applyStructuralGuards()`.
2. Suppresses heuristic matches (`PERSON`, `LOCATION`, `ORGANIZATION`) that overlap bracketed markers (`[...]`) or line-leading labels (`Agent:`, `Source:`, `Date:`).
3. Deterministic matches (`SSN`, `CREDIT_CARD`, `EMAIL`, `PHONE`, `ADDRESS`) are never suppressed.

**Outcome:**
`[START OF TRANSCRIPT]`, `[END OF TRANSCRIPT]`, `Agent (System):`, and other structural markers remain completely intact.

---

## KI-007 [RESOLVED]

### `today` masked as `[DATE]`

**Resolution:**
1. In `wink-detector.ts`, added a condition requiring `DATE` entities to contain at least one digit (`/\d/`).
2. Relative time expressions (`today`, `tomorrow`, `yesterday`) are ignored.
3. Absolute dates (`2023-10-27`, `04/12/1985`) continue to be detected and masked.

**Outcome:**
`today` remains unmasked in conversational text, while dates of birth and transcript dates are properly masked.

---

## KI-008 [RESOLVED]

### Stale compiled `.js` files beside `.ts` sources

**Resolution:**
1. Removed all compiled `.js` files from `src/pii/`.
2. Verified `tsconfig.json` outputs to `dist/`.
3. Added `src/**/*.js` to `.gitignore`.

---

## KI-009 [DOCUMENTED LIMITATION]

### Non-Latin / ASCII-only Name Limitation

**Details:**
The anchored person detection patterns (`NAME`, `FULL`) and structural token checks in `src/pii/person-detector.ts` are designed around Latin character sets (`[A-Z][a-z]`).

**Impact:**
- Non-Latin script names (such as Arabic `أحمد`, Cyrillic, Chinese, etc.) are not captured by the Latin regex anchors.
- In multilingual contexts, non-Latin person names must be supplied via `knownNames: [...]` or processed with language-specific tokenizers.
