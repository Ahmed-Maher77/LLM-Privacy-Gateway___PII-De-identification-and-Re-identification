# Improvement Plan — PII Sanitizer Remediation

> **Status: EXECUTED & VERIFIED.** All tasks (T0–T9) have been implemented and verified. All 57 tests pass. See [KNOWN-ISSUES.md](./KNOWN-ISSUES.md) for outcomes.

**Audience: an AI coding agent executing this plan.** Self-contained — you do not need
any prior conversation. Read [KNOWN-ISSUES.md](./KNOWN-ISSUES.md) and
[ARCHITECTURE.md](./ARCHITECTURE.md) before starting; do not re-diagnose from scratch.

**Repo:** TypeScript ESM, Node, vitest. `npm test` / `npm run demo` / `npm run evaluate`.
**Scope:** `src/pii/`, `src/demo.ts`, `tests/`, `docs/`. Do not touch anything else.

---

## 0. Ground truth (already verified — do not re-investigate)

These facts were established by running the code. Trust them.

| Fact | Evidence |
| --- | --- |
| `wink-eng-lite-web-model` NER has **no PERSON / ORG / LOCATION class** | Model README: trained only for CARDINAL, DATE, DURATION, EMAIL, EMOJI, EMOTICON, HASHTAG, MENTION, MONEY, ORDINAL, PERCENT, TIME, URL |
| Wink's entire NER output on `samples/large_sample.txt` | 3 DATE, 2 EMAIL, 9 CARDINAL, 1 DURATION. Zero names. |
| All 29 `[PERSON]` tags come from **our** PROPN heuristic | `src/pii/wink-detector.ts` Step 3 |
| `4111222233334321` Luhn sum = 58 → **invalid** | computed |
| `4532-0150-0000-0007` Luhn **valid**; `1111-2222-3333-4445` Luhn **invalid** | computed |
| `\b\d{3}-\d{2}-\d{4}\b` does **not** collide with `555-987-6543` or `(555) 123-4567` | tested |
| `tsx` resolves the `.ts` sources, not the stale sibling `.js` files | tested with a marker |

**Current result on `samples/large_sample.txt`:** 36 spans masked, ~11 real PII
(**~31% precision**), and SSN + credit card + full address **left unmasked**.

---

## 1. Non-negotiable constraints

1. **Offset invariant:** `text.slice(start, end) === value` for every match returned.
   Enforced by `normalizeMatches()`; every new detector must satisfy it.
2. **Non-overlapping output.** `maskPII` replaces right-to-left; never change that order.
3. **Local + deterministic only.** No network, no LLM, no new runtime dependency.
4. **Shape, not validity.** Checksums (Luhn) and issuance rules (SSA) set *confidence*;
   they must never be hard gates that discard a match.
5. **Never map a POS tag directly to a PII type.** `PROPN` means proper noun, not person.
6. **No config toggle without an emitter** for its type.
7. **Denylists are not a precision strategy.** Anchors and shape rules are.
8. Report **both** precision and recall after every change. Never only one.

---

## 2. Target output (the acceptance criteria for the whole plan)

After all tasks, `npm run demo` on `samples/large_sample.txt` must produce exactly:

```text
Test Case ID: PII-TEST-001
Date: [DATE]
Source: Customer Support Chat Log

[START OF TRANSCRIPT]

Agent (System): Thank you for contacting SecureBank Support. My name is [PERSON]. How can I help you today?

User: Hi [PERSON]. I’m having trouble logging in. My name is [PERSON], but my account might be under [PERSON].

Agent: I can help with that, Mr. [PERSON]. Can you please verify your identity? I have your date of birth listed here as [DATE].

User: Yes, that’s correct. My social security number is [SSN] if you need that.

Agent: Thank you. I see the account associated with email [EMAIL]. Is that correct?

User: Yes, but please send the reset link to my work email instead: [EMAIL].

Agent: Got it. I’ve updated the contact preference. Now, can you confirm the billing address on file?
User: It should be [ADDRESS].

Agent: Perfect. And the phone number we have on file is [PHONE].
User: Actually, my cell is better. It’s [PHONE].

Agent: Updated. For security purposes, can you confirm the last four digits of your card?
User: Sure, it’s a Visa ending in 4321. The full number is [CREDIT_CARD].

Agent: Thank you. I’ve unlocked your account. Is there anything else?
User: No, that’s all. Thanks, [PERSON].

Agent: You’re welcome. Have a great day.

[END OF TRANSCRIPT]
```

**Expected match counts:** PERSON 6, DATE 2, SSN 1, EMAIL 2, ADDRESS 1, PHONE 2,
CREDIT_CARD 1 = **15 matches, 0 false positives** (down from 36 with ~25 false positives).

Specifically these must **stay unmasked**: `Test Case ID`, `PII-TEST-001`, `Source`,
`Customer Support Chat Log`, `[START OF TRANSCRIPT]`, `[END OF TRANSCRIPT]`, `Agent`,
`System`, `SecureBank Support`, `Perfect`, `Visa`, `4321`, `today`.

---

## 3. Tasks

Execute in order. T1 is a prerequisite for T2/T3. Commit after each task.

### T0 — Delete stale build artifacts (KI-008)

Delete these; they are stale output from an old build (`tsconfig.json` emits to `dist/`)
and will mislead you while you work:

```text
src/pii/config.js  src/pii/detector.js  src/pii/masker.js  src/pii/normalizer.js
src/pii/regex-detector.js  src/pii/types.js  src/pii/wink-detector.js
```

Add `src/**/*.js` to `.gitignore` if not already covered. Verify `npm test` still passes.

---

### T1 — Add a `score` hook to `RegexRule`

**File:** `src/pii/regex-detector.ts`

Rules currently carry a fixed `confidence`. T2/T3 need per-match confidence.

```ts
interface RegexRule {
  type: PIIType;
  regex: RegExp;
  confidence: number;
  validator?: (match: string, options?: RegexDetectorOptions) => boolean;
  /** Per-match confidence. Overrides `confidence` when present. */
  score?: (match: string) => number;
  trimTrailing?: boolean;
}
```

In `detectWithRegex`, emit `confidence: rule.score ? rule.score(rawVal) : rule.confidence`.

**Acceptance:** no behaviour change; all 35 existing tests still pass.

---

### T2 — SSN: match shape, score validity (KI-002) — **Critical**

**File:** `src/pii/regex-detector.ts`

Replace the SSN rule. The current lookaheads encode SSA *issuance validity*, which is the
wrong rule for a sanitizer.

```ts
/** True if the SSN could actually have been issued by the SSA. */
export function isIssuableSSN(val: string): boolean {
  const m = /^(\d{3})-(\d{2})-(\d{4})$/.exec(val.trim());
  if (!m) return false;
  const [, area, group, serial] = m;
  if (area === '000' || area === '666' || area!.startsWith('9')) return false;
  if (group === '00') return false;
  if (serial === '0000') return false;
  return true;
}
```

```ts
{
  type: 'SSN',
  regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  confidence: 0.9,
  score: (m) => (isIssuableSSN(m) ? 0.98 : 0.9),
}
```

**Rewrite the test.** `tests/regex-detector.test.ts` currently asserts at
"detects valid US SSN formats and rejects reserved prefixes" that `000-12-3456` and
`666-12-3456` are *not* detected. That assertion encodes the bug. Replace it with:

- `123-45-6789`, `000-12-3456`, `666-12-3456` → **all three detected** as SSN.
- `123-45-6789` confidence `0.98`; `000-12-3456` confidence `0.9`.
- `555-987-6543` (a phone) → **not** detected as SSN.
- Offset invariant holds for each.
- `isIssuableSSN` unit tests: true for `123-45-6789`; false for `000-12-3456`,
  `666-12-3456`, `900-12-3456`, `123-00-6789`, `123-45-0000`.

---

### T3 — Credit card: shape + brand prefix, Luhn as confidence (KI-003) — **Critical**

**File:** `src/pii/regex-detector.ts`

```ts
/** Matches a known issuer identification number prefix. */
export function hasCardBrandPrefix(digits: string): boolean {
  if (/^4/.test(digits)) return true;                     // Visa
  if (/^5[1-5]/.test(digits)) return true;                // MasterCard
  if (/^2(2[2-9][1-9]|[3-6]\d{2}|7[01]\d|720)/.test(digits)) return true; // MC 2-series
  if (/^3[47]/.test(digits)) return true;                 // Amex
  if (/^(6011|65|64[4-9])/.test(digits)) return true;     // Discover
  if (/^3(0[0-5]|[68])/.test(digits)) return true;        // Diners
  if (/^35(2[89]|[3-8]\d)/.test(digits)) return true;     // JCB
  return false;
}
```

Keep the existing shape regex. Replace the validator and add a score:

```ts
{
  type: 'CREDIT_CARD',
  regex: /\b(?:\d{4}[ -]?){3}\d{4}\b|\b3[47]\d{2}[ -]?\d{6}[ -]?\d{5}\b/g,
  confidence: 0.85,
  validator: (m, options) => {
    const digits = m.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;
    if (isValidLuhn(digits)) return true;
    // strict mode exists so the evaluation harness can measure Luhn-only behaviour
    if (options?.strictLuhn) return false;
    // Luhn-invalid but brand-prefixed AND grouped with separators -> still disclosive
    return hasCardBrandPrefix(digits) && /[ -]/.test(m);
  },
  score: (m) => (isValidLuhn(m) ? 0.98 : 0.85),
}
```

**Rename the option.** Replace `validateCreditCardLuhn?: boolean` with
`strictLuhn?: boolean` (default `false`) in `RegexDetectorOptions`
(`src/pii/types.ts`). The old name's polarity is ambiguous. Then **grep for every call
site** — `src/pii/detector.ts` currently passes `validateCreditCardLuhn: true`, which
under the new rule would re-break the fix. It must stop passing it (or pass
`strictLuhn: false`).

**Tests** (`tests/regex-detector.test.ts`):

- `4111 2222 3333 4321` → detected, confidence `0.85` (Luhn-invalid, Visa prefix, spaced).
- `4532-0150-0000-0007` → detected, confidence `0.98` (Luhn-valid).
- `1111-2222-3333-4445` → **not** detected (Luhn-invalid, no brand prefix). Preserves the
  existing negative case.
- `1234567890123456` → **not** detected (no brand prefix, no separators, Luhn-invalid).
- With `strictLuhn: true`, `4111 2222 3333 4321` → **not** detected.
- Offset invariant holds for each.

---

### T4 — Add an ADDRESS detector (KI-004)

**File:** `src/pii/regex-detector.ts`

This regex is **already validated** against the sample — use it as given. Build it from
parts for readability; do not hand-inline it.

```ts
const STREET_SUFFIX = 'Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr'
  + '|Terrace|Ter|Court|Ct|Circle|Cir|Way|Place|Pl|Parkway|Pkwy|Highway|Hwy';

const US_STATE = 'A[LKZR]|C[AOT]|D[CE]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]'
  + '|N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AT]|W[AIVY]';

const ADDRESS_PATTERN = new RegExp(
  String.raw`\b\d{1,6}\s+(?:[A-Z][A-Za-z.]*\s+){0,4}(?:${STREET_SUFFIX})\b\.?`
  + String.raw`(?:\s+(?:NW|NE|SW|SE|N|S|E|W)\b)?`
  + String.raw`(?:\s*,\s*[A-Z][A-Za-z.]*(?:\s+[A-Z][A-Za-z.]*)*)?`
  + String.raw`(?:\s*,\s*(?:${US_STATE})\s+\d{5}(?:-\d{4})?)?`,
  'g',
);
```

Add as a `RegexRule` with `type: 'ADDRESS'`, `confidence: 0.9`.

Verified behaviour:

| Input | Match |
| --- | --- |
| `It should be 742 Evergreen Terrace, Springfield, OR 97403.` | `742 Evergreen Terrace, Springfield, OR 97403` |
| `Ship to 1600 Pennsylvania Avenue NW, Washington, DC 20500.` | `1600 Pennsylvania Avenue NW, Washington, DC 20500` |
| `350 Fifth Ave, New York, NY 10118` | full span |
| `Apt at 12 Baker St, London` | `12 Baker St, London` |
| `Order 4321 was shipped` | none |
| `I walked 5 Miles today` | none |

Because the ADDRESS span is longer than any nested match, `normalizeMatches()` rule 2
absorbs nested spans automatically — **no special-casing needed**.

**Acceptance:** all six rows above, as tests, plus the offset invariant.

---

### T5 — Replace PROPN person guessing with anchored detection (KI-001) — **the main fix**

**New file:** `src/pii/person-detector.ts`. Keep it separate; do not grow
`wink-detector.ts`.

This approach is **already prototyped and verified**: 6/6 true positives on the sample,
**0 false positives** on the control set. Use the patterns as given.

```ts
const NAME = String.raw`[A-Z][a-z]{1,20}(?:\s+(?:[A-Z][a-z]{1,20}|[A-Z]\.)){0,2}`;
const FULL = String.raw`[A-Z][a-z]{1,20}(?:\s+[A-Z]\.)?\s+[A-Z][a-z]{1,20}`;
const AP   = String.raw`['’]`; // straight AND curly apostrophe
```

Three details that cost real debugging time — do not "simplify" them away:

1. **In `NAME`, the full-word branch must come before the initial branch**, and the
   initial branch must require a literal period (`[A-Z]\.`). Reversed, `Sarah Jenkins`
   matches as `Sarah J`.
2. **No `i` flag anywhere.** The capture group relies on `[A-Z][a-z]` to reject lowercase
   words. With `/i`, `thank you for contacting` captures `for c`. Write the trigger words
   with explicit classes (`[Tt]hanks`) instead.
3. `AP` must include U+2019 — the sample uses curly apostrophes (`I’m`).

Anchors:

```ts
const ANCHORS = [
  { id: 'name-is',  re: new RegExp(String.raw`[Mm]y name(?:\s+is|${AP}s)\s+(${NAME})`, 'g'), confidence: 0.95 },
  { id: 'self',     re: new RegExp(String.raw`\b(?:I am|I${AP}m|[Tt]his is)\s+(${NAME})`, 'g'), confidence: 0.9 },
  { id: 'title',    re: new RegExp(String.raw`\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+(${NAME})`, 'g'), confidence: 0.95 },
  { id: 'greeting', re: new RegExp(String.raw`\b(?:[Hh]i|[Hh]ello|[Hh]ey|[Dd]ear|[Tt]hanks|[Tt]hank you|[Rr]egards|[Ss]incerely)[,!]?\s+(${NAME})`, 'g'), confidence: 0.85 },
  { id: 'account',  re: new RegExp(String.raw`\b(?:under|account of|on behalf of|policyholder)\s+(${FULL})`, 'g'), confidence: 0.9 },
  { id: 'speaking', re: new RegExp(String.raw`(${FULL})\s+speaking\b`, 'g'), confidence: 0.9 },
];
```

Note `account` and `speaking` use `FULL` (requires two name tokens) because their
triggers are weaker. Do **not** add `customer` as a trigger — it captures
`Customer Support Chat Log`.

Shape validator applied to every capture:

```ts
const ROLE_WORDS = new Set([
  'agent','user','system','customer','support','admin','operator',
  'team','bot','assistant','sorry','thanks','yes','no',
]);

function isPlausibleName(value: string): boolean {
  const tokens = value.trim().split(/\s+/);
  if (tokens.length > 3) return false;
  for (const token of tokens) {
    const bare = token.replace(/\.$/, '');            // "T." -> "T"
    if (/\d/.test(bare)) return false;                 // PII-TEST-001
    if (bare.length > 1 && bare === bare.toUpperCase()) return false; // TRANSCRIPT, END
    if (ROLE_WORDS.has(bare.toLowerCase())) return false;
  }
  return true;
}
```

`bare.length > 1` on the all-caps check is load-bearing: without it the middle initial
`T.` is rejected and `Michael T. Rodriguez` is lost.

Offset extraction: `const start = m.index + m[0].lastIndexOf(capture);` — the anchor
prefix is not part of the span. Assert `text.slice(start, end) === capture`.

Also support **exact-match masking from a caller-supplied list**, which is how unanchored
names are recovered:

```ts
export interface PersonDetectorOptions {
  knownNames?: string[];   // word-boundary exact match, confidence 0.99
}
```

**Config** (`src/pii/types.ts`, `src/pii/config.ts`):

```ts
personStrategy?: 'off' | 'anchored' | 'propn';   // default 'anchored'
knownNames?: string[];                            // default []
```

Keep `person?: boolean` as the master switch — when `person: false`, no person detection
regardless of strategy. Retain `'propn'` so the evaluation harness can still measure the
old behaviour, but **never** as the default.

**Wiring** (`src/pii/detector.ts`):

```ts
if (resolved.person) {
  if (resolved.personStrategy === 'anchored') {
    rawMatches.push(...detectPersons(text, { knownNames: resolved.knownNames }));
  }
  // 'propn' keeps flowing through detectWithWinkNLP; 'off' emits nothing
}
```

and pass `extractProperNounsAsPerson: resolved.person && resolved.personStrategy === 'propn'`.

**Tests** (`tests/person-detector.test.ts`, new):

- Each of the 6 anchors fires on a positive example.
- Must detect: `Sarah Jenkins`, `Michael T. Rodriguez`, `Mike Rodriguez`, `Rodriguez`
  (from `Mr. Rodriguez`), `Sarah` ×2.
- Must **not** detect, from real sample lines: `Agent`, `System`, `Perfect`, `Visa`,
  `TRANSCRIPT`, `END`, `PII-TEST-001`, `Customer Support`, `for contacting`.
- `knownNames: ['Evergreen']` → detected; empty list → no effect.
- Offset invariant on every match.
- Empty string, whitespace-only, and 10k-char input without names → `[]`, no throw.

---

### T6 — Structural guards (KI-006)

**New file:** `src/pii/structure.ts`

```ts
/** Ranges where heuristic (non-deterministic) matches must be suppressed. */
export function getProtectedRanges(text: string): Array<[number, number]>;
```

Protect: bracketed markers `\[[^\]\n]*\]` and line-leading labels
`/^[A-Za-z][A-Za-z ]{0,20}:/gm`.

Apply **only** to `PERSON`, `LOCATION`, `ORGANIZATION`. Never to `EMAIL`, `PHONE`, `SSN`,
`CREDIT_CARD`, `ADDRESS`, `IP_ADDRESS`, `URL` — a card number legitimately appears after
a `Card:` label and must still be masked. **This distinction is the whole point of the
task; getting it wrong reintroduces a leak.**

After T5 the guards are defence-in-depth rather than load-bearing (the anchors already
produce 0 false positives here), so keep the implementation minimal.

**Tests:** a `PERSON` inside `[START OF TRANSCRIPT]` is suppressed; an `SSN` after
`SSN: 123-45-6789` is **not** suppressed.

---

### T7 — Narrow DATE to absolute dates (KI-007)

**File:** `src/pii/wink-detector.ts`

Wink tags `today` as `DATE`. Relative expressions are not PII. In the DATE branch,
require the value to contain a digit:

```ts
if (piiType === 'DATE' && !/\d/.test(value)) return;
```

**Acceptance:** `2023-10-27` and `04/12/1985` still mask; `today`, `tomorrow`,
`yesterday` do not.

*Optional refinement, only if cheap:* anchor birth context (`date of birth`, `DOB`,
`born`) for a higher-confidence DOB signal, so the document header date could be left
unmasked. Not required for the target output above, which masks both dates.

---

### T8 — Stop the dead toggles lying (KI-004)

**File:** `src/pii/config.ts`

`address`, `location`, `organization` are `true` by default but nothing emits them. T4
fixes `address`. For the other two, pick **one** and be consistent:

- **Preferred:** set `location: false` and `organization: false` in `DEFAULT_PII_CONFIG`,
  and add `knownLocations?: string[]` / `knownOrganizations?: string[]` using the same
  exact-match helper as `knownNames`. Then the toggles have a real emitter.
- **Alternative:** remove `LOCATION` and `ORGANIZATION` from `PIIType` entirely.

Do not leave them `true` with no emitter.

---

### T9 — Regression test, measurement, and docs

1. **New test** `tests/sample-regression.test.ts`: run the demo config over
   `samples/large_sample.txt` and assert the masked output **equals the target block in
   section 2 verbatim**, plus assert the per-type counts. This is the guard against
   regression and the single most valuable test in the suite.

2. **Update `src/evaluate.ts`.** Be aware the anchored strategy **intentionally trades
   recall for precision** on unanchored names. These existing dataset cases will no
   longer match and that is correct, not a bug:

   | Case | Behaviour | Why |
   | --- | --- | --- |
   | `basic-person-1` "My name is Ahmed." | still detected | `name-is` anchor |
   | `mixed-text-1` "Hello Ahmed, ..." | still detected | `greeting` anchor |
   | `multi-pii-1` "My name is Ahmed Maher." | still detected | `name-is` anchor |
   | `basic-person-2` "Barack Obama visited London." | **no longer detected** | no anchor — this is KI-005, the real model limit |
   | `repeated-pii-1` "Ahmed contacted Ahmed..." | **no longer detected** | no anchor |
   | Arabic `أحمد` | not detected | `NAME` is ASCII-only — document as a limitation |

   Split the dataset into **anchored** and **unanchored** cohorts and report precision and
   recall per cohort per strategy (`off` / `anchored` / `propn`). A single blended number
   hides the trade-off. Show that `knownNames` recovers the unanchored cohort.

3. **Update the docs in the same change** (required by `AGENTS.md`):
   - `docs/KNOWN-ISSUES.md` — mark KI-001..KI-004, KI-006..KI-008 resolved, or remove
     them. Keep **KI-005** (it is a genuine model limit, not fixable here). Add the
     ASCII-only name limitation.
   - `docs/ARCHITECTURE.md` — add `person-detector.ts` and `structure.ts` to the pipeline
     diagram and module map; document the `personStrategy` switch.
   - `docs/WINKNLP-CAPABILITIES.md` — no change expected.

---

## 4. Verification before you report done

```bash
npm test                 # all tests green, including the new ones
npm run demo             # output must equal section 2 verbatim
npm run evaluate         # per-cohort precision/recall for all 3 strategies
npm run benchmark        # confirm no latency regression
npx tsc --noEmit         # zero type errors
```

Report, explicitly:

- Before/after **precision and recall** on `samples/large_sample.txt` — both numbers.
- Before/after on the evaluation dataset, **split by anchored vs unanchored cohort**.
- Any case where recall dropped, and whether `knownNames` recovers it.
- Any acceptance criterion you could not meet, and why.

---

## 5. Do not do these

- Do not add a dependency, a network call, or an LLM to the detection path.
- Do not "fix" KI-001 by extending `NON_PERSON_WORDS`. Delete that denylist as part of T5.
- Do not make `personStrategy: 'propn'` the default, and do not delete it — the
  evaluation harness measures it.
- Do not apply the T6 structural guards to deterministic types. That reintroduces a leak.
- Do not keep Luhn or SSA issuance rules as hard gates anywhere.
- Do not change `maskPII`'s right-to-left replacement order.
- Do not weaken the offset invariant to make a detector easier to write.
- Do not leave TODOs. Do not modify files outside `src/pii/`, `src/demo.ts`, `tests/`,
  `docs/`.
- Do not report success on the basis of `npm test` alone — the current suite passes
  **while the sanitizer leaks an SSN and a card number**. Section 2 is the real gate.
