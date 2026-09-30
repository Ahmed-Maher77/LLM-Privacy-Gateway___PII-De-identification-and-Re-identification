# NER layer design: Transformers.js

**Status: built and tuned (PLAN.md Phases 1–2).** It replaces the Presidio
layer (`src/pii/layers/presidio.ts`, `src/pii/client.ts`, `presidio/`), which
stays in the repo, unused, until Phase 4. Until then README.md and
ARCHITECTURE.md describe the Presidio-based pipeline. The steps are in
[PLAN.md](PLAN.md); the chosen model, settings and numbers are in "Choice and
numbers" at the end.

## Goal

Detect names in-process with a local ONNX model through
[Transformers.js](https://huggingface.co/docs/transformers.js), so the pipeline
needs no Docker, no sidecar and no network at run time. Everything else stays
as it is: the other layers, the merge step, placeholders, the output files and
the `redact()` / `detect()` API.

## Pipeline after the change

```text
file ─▶ src/index.ts ─▶ redact() ─▶ detect()
                                      ├─ 1. pre-defined list   layers/predefined.ts
                                      │     name lists         layers/dictionary.ts  (data/lists/)
                                      ├─ 2. regex              layers/regex.ts
                                      ├─ 3. NER model          layers/ner.ts ──▶ models/<model>/ (local ONNX)
                                      ├─ 4. wink-nlp           layers/wink.ts
                                      ├─ every occurrence of a found value
                                      └─ merge overlaps
                         ─▶ Placeholders (policy.ts) ─▶ reports/<name>__sanitized.txt
```

## What changes, file by file

| File | Change |
| --- | --- |
| `src/pii/layers/ner.ts` | **New.** Loads the model and returns spans (sections below) |
| `src/pii/layers/ner_models.ts` | **New.** Per model: pinned revision, files with SHA-256, the label that means PERSON. Shared by `ner.ts` and `fetch-model.ts` |
| `src/pii/layers/presidio.ts` | Deleted. `looksLikePerson` moves to `ner.ts`; `trimName` and the IPv4 filter are no longer needed (sections 4–5) |
| `src/pii/client.ts`, `presidio/` | Deleted |
| `src/pii/redact.ts` | Call `detectNer()` instead of `detectPresidio()`; `"presidio"` in `LAYER_ORDER` becomes `"ner"` |
| `src/pii/types.ts` | `PIISpan.source` gets `"ner"`. `"presidio"`, `PresidioRecognizerResult` and `AnalyzeRequest` stay until Phase 4, since `presidio.ts` and `client.ts` still use them |
| `src/index.ts` | `PresidioUnavailableError` becomes `ModelLoadError`, still exit code 2 |
| `src/pii/layers/regex.ts` | Covers what only Presidio caught (see "Regex additions"); `libphonenumber-js` validates international numbers |
| `scripts/fetch-model.ts` | **New.** `npm run fetch:model` downloads the pinned model into `models/` |
| `scripts/check-offsets.ts` | **New.** `npm run check:offsets`: the offset tests of PLAN.md 1.5 |
| `package.json` | Add `@huggingface/transformers` (pinned exact) and `fetch:model`; remove `presidio:up` / `presidio:down` (Phase 4) |
| `.gitignore` | Add `models/` (unless we decide to commit the model, see PLAN.md) |

## Why we don't use `pipeline("token-classification")`

Checked in the `@huggingface/transformers` 4.3.0 source
(`src/pipelines/token-classification.js`):

1. **It gives no character offsets.** Results have `word`, `score`, `entity`
   and `index`; `start` / `end` are marked `// TODO`. We need exact offsets
   into the original text.
2. **It truncates silently.** It tokenizes with `truncation: true`, so text
   past the model's 512 tokens is never looked at. That would be a quiet leak.

So `ner.ts` calls `AutoTokenizer` and `AutoModelForTokenClassification`
directly and works out the offsets itself.

## How `ner.ts` works

### 1. Loading (once per process)

```ts
import type { PreTrainedModel, PreTrainedTokenizer } from "@huggingface/transformers" with { "resolution-mode": "import" };

const { env, AutoTokenizer, AutoModelForTokenClassification, Tensor } = await import("@huggingface/transformers");
env.allowRemoteModels = false;             // never download at run time
env.localModelPath = MODELS_DIR;           // models/
// tokenizer + model loaded once and kept in a module-level promise
```

The package is an ES module (`"type": "module"`). A static `import` from this
CommonJS project runs under tsx but fails `tsc` with TS1479, so values come
from a dynamic `import()` and types from `import type` with
`resolution-mode: "import"`.

- The model loads lazily on the first call, and every later call reuses the
  same promise.
- `[CLS]` / `[SEP]` come from `tokenizer.encode("")`, the model's own
  template: `tokenizer.cls_token_id` is `undefined` in 4.3.0. The model is
  called with `input_ids` and `attention_mask` only; the ONNX graph has no
  `token_type_ids` input.
- Use the quantized weights (`dtype: "q8"`, file `onnx/model_quantized.onnx`)
  on the CPU (`onnxruntime-node`). The fp32 model was slower here, and 4× larger.
- Set onnxruntime's intra-op threads explicitly (`NER_THREADS`, default half
  the logical CPUs, i.e. one per physical core with hyper-threading). Its own
  default ran about as fast as 2 threads on an 8-core / 16-thread machine.
- If any file is missing or doesn't load, throw `ModelLoadError` ("Run `npm run
  fetch:model`"). The CLI exits with code 2 and writes nothing, as it does for
  Presidio today.

### 2. Pieces: offsets come from our own split

The text is split into **pieces**, each with its exact UTF-16 `start`/`end`:

```ts
const PIECE_RE = /[^\s\p{P}\p{S}]+|[\p{P}\p{S}]/gu;  // runs of letters/digits, or one punctuation mark
```

This is close to the split BERT's own pre-tokenizer makes (whitespace, then
punctuation), so the model sees nearly the same input as usual. One
difference: BERT counts only ASCII symbols as punctuation, so it keeps an emoji
or "©" attached to the word next to it, where we split it off. That never
splits a name. Each piece is
tokenized on its own (`tokenizer.encode(piece, { add_special_tokens: false })`)
into one or more sub-tokens. Results are cached by piece string, since
transcripts repeat words a lot. A piece that tokenizes to nothing (a lone
zero-width character) is skipped: it is not labelled and doesn't end a span.

**The model never gives offsets.** It labels pieces, and a piece's offsets are
the ones our regex found. Before returning, assert `span.text ===
text.slice(span.start, span.end)` for every span and throw if it fails, the
same guard `wink.ts` has.

A piece's label is the label of its **first sub-token**, with that
sub-token's softmax probability as the score.

> SentencePiece models (XLM-R, DeBERTa) mark word starts with `▁`, and
> tokenizing a piece on its own always marks it as a word start ("Sarah," →
> "Sarah" + ","). That is a small change from normal input; measure its effect
> before choosing such a model.

### 3. Windows: no truncation

- Pieces are packed into windows of at most `NER_WINDOW_TOKENS` sub-tokens
  (default 384, hard maximum 510, plus `[CLS]`/`[SEP]`).
- Consecutive windows overlap by 32 sub-tokens.
- A piece that appears in two windows takes the label from the window where
  it is further from a **cut** edge, since it has more context there. The
  start of the first window and the end of the last are the text's own ends,
  not cuts, so they don't count as edges.
- One window per model call, with no padding: batching padded windows was
  slower on the CPU.
- A single piece longer than a window (a base64 blob, say) is labelled `O`.
  It is not a name, and regex still sees it.

Every piece gets exactly one label, so nothing past token 512 goes unread.
`ner.ts` checks this and throws if any piece was left unlabelled.

### 4. Labels to spans

**Only PERSON is taken from the model.** Regex covers every other type with
100% recall on the labelled set, and the model's other types cost precision
(its DATE_TIME alone added 153 false positives: times, durations, "today").
Each model's PERSON label is in `ner_models.ts` (`PERSON` for gravitee).

Walk the labelled pieces in order:

- `B-PERSON` starts a span; `I-PERSON` continues an open span, or starts one
  if none is open (models do emit a stray `I-`).
- A span is made of **letter pieces**, and may continue across the joiners
  `.` `'` `’` `-` ("Al-Rashid", "O'Brien", "L. Picard"). Anything else ends it:
  `O`, other punctuation, a piece with a digit, or a **line break**. A span
  never ends on a joiner.
- A span's score is the mean of its letter pieces' scores.
- **Adjacent spans are joined** when they are on one line and separated only
  by spaces/tabs or a single `.`. The model often tags each word of a name
  `B-` ("kofi mensah" → `B-PERSON B-PERSON`); joined, the name gets one
  placeholder, and initials leave nothing visible ("J" + "." + "L. Picard").
  A joined span takes its stronger part's score.
- Spans under `NER_MIN_SCORE` are dropped, **after** joining, so a name is kept
  or dropped as a whole: a surname scored 0.49 next to a first name scored 0.94
  stays masked.

### 5. Filters

Applied after joining and the score check, in `ner.ts`, reusing
`dictionary_helpers.ts`:

- **Trim the edges.** Titles (`TITLES`: "Mr", "Dr.") are stripped at both
  ends; leading words that are English words but not listed given names are
  stripped at the start ("Agent David" → "David"). A span with nothing left
  is dropped ("Mr", "Audio"). "Grace" and "Will" stay: they are listed given
  names. This replaces `presidio.ts`'s "only English words" rule.
- **Greetings and fillers:** a span made only of `NEVER_NAMES` ("Salam") is
  dropped.
- **Acronyms:** a span made only of all-caps words (`isAllCaps`: "FHIR",
  "AA") is dropped, unless the rest of its line is in capitals too.
- **Lowercase names only on lowercase lines:** a lowercase span on a line that
  has capitals is dropped (kept from `presidio.ts`).

`trimName` is gone: spans can no longer cross a line break, hold a word with
a digit, or end on punctuation. The IPv4 filter is gone with the model's
PHONE_NUMBER.

Why "Agent" needed the edge trim: the model's span was "Agent David" (from
"captured between Agent David and customer Robert Miller"). The
every-occurrence step in `redact.ts` masks each capitalised part of a found
name everywhere, so "Agent" was then masked on every line. Trimming at the
source fixes it without changing `redact.ts` for the other layers.

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `NER_MODEL` | `gravitee-io/bert-small-pii-detection` | folder under `models/`; must be in `ner_models.ts` |
| `NER_MIN_SCORE` | `0.5` | name spans below it are dropped (after joining) |
| `NER_WINDOW_TOKENS` | `384` | at most 510 |
| `NER_THREADS` | half the logical CPUs | onnxruntime intra-op threads |

`PRESIDIO_ANALYZER_URL` and `PRESIDIO_ANALYZER_WORKERS` go away.

## Model candidates

Checked on Hugging Face on 2026-09-30:

| Model | Licence | Quantized size | Cased | Labels we'd use | Notes |
| --- | --- | --- | --- | --- | --- |
| `gravitee-io/bert-small-pii-detection` | Apache-2.0 | 29 MB | **no** | PERSON | **Chosen** (see below). Its ONNX files are at the repo root (`model.quant.onnx`), so `fetch:model` moves them to `onnx/model_quantized.onnx` |
| `Xenova/bert-base-NER` | MIT | 109 MB | yes | PER | Scored once with the same filters: fails the criteria (below) |
| `Xenova/distilbert-base-multilingual-cased-ner-hrl` | AFL-3.0 (upstream `Davlan/…`) | ~135 MB | yes | PER | Covers several languages including Arabic script |
| `bardsai/eu-pii-anonimization-multilang` | Apache-2.0 | 279 MB | yes | PERSON_NAME | XLM-R, multilingual, PII-specific. Large and slower |
| ~~`iiiorg/piiranha-v1-…`~~ | CC-BY-NC-ND-4.0 | — | — | — | **Excluded: licence forbids commercial use** |

## Regex additions

Only three values in the saved `reports/` came from Presidio and no other
layer. `regex.ts` has to cover them before Presidio is gone:

| Missed by regex | Example | Fix |
| --- | --- | --- |
| Phone numbers in single- or two-digit groups | `+33 6 12 34 56 78` | **Done in Phase 2** (it leaked once the model's PHONE_NUMBER was dropped): a `+`-prefixed candidate regex, validated with `libphonenumber-js` `isValidPhoneNumber`. `findPhoneNumbersInText` was not used: it over-extends (`+1-202-555-0147, 617`) |
| Passport with no keyword right before it | `"A38291049"` a few words after "passport" | **Done in Phase 3:** the US passport shape (`[A-Z]\d{8}` or 9 digits) anywhere on a line with "passport" (no letter before it, so `US_PASSPORT:` counts) |
| (Presidio behaviour we should copy) | `000-12-3456` | **Done in Phase 3:** both SSN rules skip area 000, 666 or 900–999, group 00, serial 0000. `test_data/regex_edge.txt` has five such numbers, unlabelled, so masking one would show as a false positive |

## Design rules (unchanged)

- **Offsets come from the original text.** Pieces are found by regex over the
  original text, and every span is checked against it.
- **Fail closed.** If the model is missing or won't load, or the input is over
  2,000,000 characters, the run stops with no output.
- **Merging favours masking.** When layers disagree about where a value ends,
  the union is masked.

## Choice and numbers (Phase 2, 2026-09-30)

**Model: `gravitee-io/bert-small-pii-detection`** @ `f8c27a8`, q8, PERSON
only, `NER_MIN_SCORE` 0.5, window 384 / overlap 32, one window per call, 8
threads. Measured on an 8-core / 16-thread i7-11850H, Windows.

Scores on the labelled `test_data/` (`npm run eval`), against the
Presidio-era reference:

| | Now | Reference |
| --- | --- | --- |
| PERSON recall, normally cased files | 318 / 319 (99.7%) | 318 / 319 (99.7%) |
| PERSON characters leaked, `asr_sample.txt` | 8 / 74 (10.8%) | 18 / 74 (24.3%) |
| PERSON false positives | 6 | 7 |
| PERSON recall / leaked / precision | 99.1% / 0.5% / 98.2% | 98.5% / 0.9% / 97.9% |
| All types: recall / leaked / precision | 99.2% / 0.4% / 98.4% | 98.7% / 0.7% / 94.2% |

Every other type has 100% recall and 100% precision. Hard labels: 0 / 10
found, as in the reference (Phase 1's 4 came from the model's other types).

**`NER_MIN_SCORE`:** 0.1–0.5 score the same; 0.6 also drops "Sarahville"; 0.7
loses "David" (×11 through every-occurrence). 0.5 keeps a 0.2 margin to that
drop.

**What each step did** (PERSON false positives, from 30 in Phase 1): PERSON
only 30 (and one phone leaked, fixed in regex); letter/joiner grouping 30;
edge trim, `NEVER_NAMES`, acronyms 5; joining 5 and "J.L. Picard" found;
window 384 6 ("Sarahville").

**Speed** (`redact()`; 229 KB warm is the mean of 2 runs, 6 KB cold is
a fresh process):

| Setting | 229 KB warm |
| --- | --- |
| Phase 1: q8, window 256/64, batch 8, onnxruntime's default threads | 10.2 s |
| fp32 instead of q8 (default threads / 8 threads) | 11.5 s / 9.5 s |
| q8, 256/64, batch 8, threads 1 / 2 / 4 / 8 / 16 | 31.4 / 11.1 / 7.5 / 6.6 / 8.7 s |
| q8, 8 threads, window 384/32 or 510/32, batch 8 | 6.8 / 7.9 s |
| q8, 8 threads, 256/64, batch 1 / 16 | 6.7 / 7.3 s |
| q8, 8 threads, 384/32, batch 1 / 2 / 4 | 5.5 / 5.7 / 6.3 s |
| q8, 384/32, batch 1, threads 6 / 12 | 5.4 / 5.1 s |
| **Chosen: q8, 384/32, one window per call, 8 threads** | **5.2 s** (cold 6.3 s) |

| 6 KB (`mockup_interview.txt`), cold | Phase 1 | Now |
| --- | --- | --- |
| Name lists | — | 0.39 s |
| Model load (import, tokenizer, ONNX session) | — | 0.59 s |
| Compute (all layers) | — | 0.20 s |
| **Total `redact()`** | 1.7 s | **1.22 s** |

The 229 KB file is 58,436 sub-tokens; about 90% of its time is onnxruntime's
`session.run`, so the model's own compute sets the floor. The 3.8 s target
(Presidio's) is not met: 5.2 s warm.

**`Xenova/bert-base-NER`** (MIT, cased, 109 MB), same filters, 0.5: PERSON
recall on cased files 317 / 319, lowercase leak 18 / 74 (no better than the
reference), 11 false positives ("Will" ×6, "Luhn"), 17.1 s warm for 229 KB.
At 0.7 false positives fall to 5 but "Eman" ×5 is missed. It fails the
criteria, so gravitee stays; the multilingual models were not scored.

**Remaining PERSON misses:** "will" and "will mensah" in `asr_sample.txt`
(only "will" leaks), "May" in *call May tomorrow*. **False positives:**
"Lua" ×4, "grace" in *grace period*, "Sarahville" (a made-up place).
