# Plan: replace Presidio with Transformers.js

The target design is in [DESIGN.md](DESIGN.md). This file covers the order of
work, what "done" means for each phase, and the decisions still open.

## Scope

**In scope:** replace Presidio's name detection with a local Transformers.js
model, cover in `regex.ts` the few values only Presidio caught, and remove
Presidio completely.

**Not in scope:** new entity types, Arabic, an HTTP service, and changes to the
output format or to the `redact()` / `detect()` API.

**Done when:**

1. `npm install`, `npm run fetch:model` and `npm run dev -- <file>` work with
   Docker not installed and the network off (after the one-time fetch).
2. Searching `src/`, `scripts/` and `package.json` for "presidio" (case
   ignored) finds nothing.
3. On the labelled `test_data/`, compared with the Presidio-era reference
   (Phase 0):
   - PERSON recall is no lower on normally cased files
   - fewer name characters leak in `asr_sample.txt`
   - no other type loses recall
   - PERSON false positives are no more than the reference (7: Lua ×4,
     Bluetooth, Deep Dive, SQLCipher). ORGANIZATION false positives stay
     excluded (see the reference notes)
4. A 6 KB file takes at most ~1.5 s end to end, model load included. Measure
   229 KB too.
5. README.md, ARCHITECTURE.md and LIMITATIONS.md describe the new pipeline,
   with new measured numbers.

## Phase 0: evaluation first (no model yet)

Without a way to score output we can't pick a model or a threshold. There are
no labelled sets in the repo and `test_data/expected/` doesn't exist.

| # | Task | Output |
| --- | --- | --- |
| 0.1 | Run `git init` and commit the current state, so every later change can be diffed and reverted | first commit |
| 0.2 | Label each `test_data/*.txt`: the PII values per type, e.g. `{ "PERSON": ["Kofi Mensah", "kofi", "Priya"], "CREDIT_CARD": ["4539 1488 0343 6467"] }`. Claude drafts, a person reviews. Format (context-only matches, `hard`, `ignore`) in `scripts/eval/labels.ts` | `test_data/labels/<name>.json` |
| 0.3 | `scripts/evaluate.ts` (`npm run eval`): for each file and type, report recall (labelled occurrences fully masked), leaked characters, and precision (detected spans that overlap a labelled value) | a table per file and in total |
| 0.4 | Score the saved Presidio-era outputs. They are copied unchanged to `test_data/reference/`, since `npm run dev` overwrites `reports/`. Their spans are recovered by aligning each placeholder with the original, so precision is scored too. They predate some rule changes, so treat them as a rough reference | reference numbers below |

**Exit:** `npm run eval -- --reference` prints the reference numbers;
`npm run eval` scores the current pipeline and compares it with them.

### Reference numbers (Presidio era, 2026-09-30)

From `npm run eval -- --reference`, 7 files. Leaked characters leave out
whitespace. Hard labels (spelled or spoken forms, the spoken birth
date, Arabic script, checksum-failing card and IBAN) are counted apart.

| Type | Labelled | Recall | Leaked chars | Precision |
| --- | --- | --- | --- | --- |
| PERSON | 332 | 98.5% | 21 / 2394 (0.9%) | 97.9% (7 FP) |
| ORGANIZATION | 2 | 100% | 0 / 21 | 11.1% (16 FP) |
| EMAIL_ADDRESS | 11 | 100% | 0 / 273 | 100% |
| PHONE_NUMBER | 10 | 100% | 0 / 136 | 100% |
| CREDIT_CARD | 3 | 100% | 0 / 48 | 100% |
| IBAN_CODE | 2 | 100% | 0 / 54 | 100% |
| DATE_TIME | 5 | 100% | 0 / 38 | 100% |
| US_SSN | 4 | 100% | 0 / 44 | 100% |
| US_PASSPORT | 5 | 100% | 0 / 45 | 100% |
| US_DRIVER_LICENSE | 2 | 100% | 0 / 24 | 100% |
| **All types** | **376** | **98.7%** | **21 / 3073 (0.7%)** | **94.2% (23 FP)** |
| Hard (apart) | 10 | 0% | 132 / 166 (79.5%) | — |

The "Done when" criteria against this reference:

- PERSON recall on normally cased files: **318 / 319 (99.7%)**. The one miss
  is "May" in *call May tomorrow* (test_2).
- PERSON characters leaked in `asr_sample.txt`: **18 / 74 (24.3%)**, from
  "grace" ×2, "will" and "will mensah".
- PERSON false positives: **7** (Lua ×4, Bluetooth, Deep Dive, SQLCipher).

Notes:

- The 16 ORGANIZATION false positives (Redis, RabbitMQ, Datadog, … in test_3)
  come from before companies were taken only from the pre-defined list. Today's
  rules would not produce them, so don't count them in the comparison.
- Of the hard labels, the checksum-failing card in test_5 was partly masked
  (as a phone number); none was fully masked.

## Phase 1: build the NER layer

| # | Task |
| --- | --- |
| 1.1 | `npm install @huggingface/transformers@4.3.0 --save-exact`. Check that it imports and typechecks in this CommonJS / `node16` project; the package ships `dist/transformers.node.cjs`. If types don't resolve, fix it here before writing anything else |
| 1.2 | `scripts/fetch-model.ts`: download the files for a pinned model **revision** (commit hash) into `models/<org>/<name>/`, check their SHA-256, and lay them out as Transformers.js expects. Start with `gravitee-io/bert-small-pii-detection` |
| 1.3 | `src/pii/layers/ner.ts` as in DESIGN.md: loading, pieces, windows, label grouping, moved filters, offset assertion, `ModelLoadError` |
| 1.4 | Wire `detectNer()` into `redact.ts` in place of `detectPresidio()`; update `types.ts` and `index.ts` |
| 1.5 | Offset test inputs: emoji and other characters outside the BMP, CRLF line endings, a name right at a window boundary, a 229 KB file. Every span must equal `text.slice(start, end)` |

**Exit:** with Docker stopped, `npm run dev` runs on every `test_data` file
and `npm run eval` scores it.

### Phase 1 results (gravitee, untuned, 2026-09-30)

`NER_MIN_SCORE` 0.5, window 256, batch 8; all our types but ORGANIZATION
taken from the model. `npm run check:offsets` passes.

| | Current | Reference |
| --- | --- | --- |
| PERSON recall, normally cased files | 318 / 319 (99.7%) | 318 / 319 (99.7%) |
| PERSON characters leaked, `asr_sample.txt` | 8 / 74 (10.8%) | 18 / 74 (24.3%) |
| PERSON false positives | **30** | 7 |
| All types: recall / leaked / precision | 99.2% / 0.3% / 65.5% | 98.7% / 0.7% / 94.2% |
| Hard labels found | 4 / 10 | 0 / 10 |

Every type keeps 100% recall except PERSON (99.1%, reference 98.5%). The
precision losses are listed in DESIGN.md "Found while building".

Speed (`redact()`, median of 3 fresh processes):

| File | Cold (model load included) | Warm |
| --- | --- | --- |
| 5.9 KB (`mockup_interview.txt`) | 1.7 s | 0.27 s |
| 229 KB (test_data repeated) | 10.4 s | 9.0 s |

Criterion 4 (≤ ~1.5 s cold for 6 KB) is not met yet; that is Phase 2.5.

## Phase 2: choose the model and tune it

| # | Task |
| --- | --- |
| 2.1 | Score each candidate in DESIGN.md: gravitee first, then `Xenova/bert-base-NER`, then the multilingual ones |
| 2.2 | For the best one or two, sweep `NER_MIN_SCORE` (e.g. 0.3–0.9) and `NER_WINDOW_TOKENS` (128 / 256 / 384) |
| 2.3 | Re-check each moved filter (`looksLikePerson`, `trimName`, IPv4) by running with and without it, and keep only those that help |
| 2.4 | Decide which model labels to use: PERSON only, or also types the regex layer already covers (as a safety net, if precision holds) |
| 2.5 | Measure speed (6 KB and 229 KB, cold and warm) and peak memory |
| 2.6 | Record the choice, threshold and numbers in DESIGN.md; set the defaults in `ner.ts` |

**Exit:** criteria 3 and 4 of "Done when" are met. If no candidate meets
them, stop and decide with the team (for example, fine-tune on our own
transcripts) before going on.

## Phase 3: regex gaps

The three items in DESIGN.md "Regex additions": `libphonenumber-js` for
international phone numbers, the passport shape with the keyword on the same
line, and invalid-SSN filtering. Label an example of each in `test_data/`.

**Exit:** `+33 6 12 34 56 78` and `A38291049` from the saved reports are
masked again, and `npm run eval` shows no other type losing recall.

## Phase 4: remove Presidio and update the docs

| # | Task |
| --- | --- |
| 4.1 | Delete `src/pii/client.ts`, `src/pii/layers/presidio.ts` and `presidio/`; remove the `presidio:*` scripts and `PRESIDIO_*` variables |
| 4.2 | Replace README.md, ARCHITECTURE.md and LIMITATIONS.md with the new pipeline (using DESIGN.md as the source), then delete or archive this folder |
| 4.3 | `npm run check -- --update` after reading the diff of every file, and commit `test_data/expected/` |
| 4.4 | `npm run typecheck`, `npm run check` and `npm run eval` all pass; the "presidio" search is clean |

## Open decisions

| Decision | Options | Suggestion |
| --- | --- | --- |
| Where the model lives | Fetch with `npm run fetch:model` (git-ignored), or commit it (29–279 MB, Git LFS) | Fetch, pinned by revision and checksum. Commit it only if runs must work on machines that never had network |
| Types taken from the model | PERSON only, or more | Decide on the Phase 2 numbers |
| Who reviews the labels | — | Someone who knows the transcripts. Labels decide every later choice |
| Arabic | Now or later | Later. Picking a multilingual model in Phase 2 keeps the door open |

## Risks

| Risk | Effect | Mitigation |
| --- | --- | --- |
| The new model finds fewer names than spaCy | More names leak | Phase 0 scoring, the "Done when" criteria, and the stop point in Phase 2 |
| More false-positive names | The every-occurrence rule masks the same wrong word everywhere | Precision in `npm run eval`, and a word-by-word read of the check diffs |
| Only 7 small labelled files | The chosen threshold may not carry over to real transcripts | Add a few real, anonymised transcripts to `test_data/` if possible |
| Transformers.js 4.x API changes | Code breaks on upgrade | Pinned exact version; upgrade on purpose, re-running `eval` |
| `onnxruntime-node` native binary | Install trouble on some machines or CI | Check on every OS we run on during Phase 1 |
| Model download at install time | Setup fails offline | The model is fetched once; a missing model fails closed with a clear message |
