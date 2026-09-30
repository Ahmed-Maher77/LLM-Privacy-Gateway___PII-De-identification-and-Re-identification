# NER layer design: Transformers.js

**Status: built (PLAN.md Phase 1), not tuned yet.** It replaces the Presidio
layer (`src/pii/layers/presidio.ts`, `src/pii/client.ts`, `presidio/`), which
stays in the repo, unused, until Phase 4. Until then README.md and
ARCHITECTURE.md describe the Presidio-based pipeline. The steps are in
[PLAN.md](PLAN.md); what Phase 1 changed in this design is under "Found while
building" at the end.

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
| `src/pii/layers/ner_models.ts` | **New.** Per model: pinned revision, files with SHA-256, label map. Shared by `ner.ts` and `fetch-model.ts` |
| `src/pii/layers/presidio.ts` | Deleted. `trimName`, `looksLikePerson` and the IPv4 filter move to `ner.ts` |
| `src/pii/client.ts`, `presidio/` | Deleted |
| `src/pii/redact.ts` | Call `detectNer()` instead of `detectPresidio()`; `"presidio"` in `LAYER_ORDER` becomes `"ner"` |
| `src/pii/types.ts` | `PIISpan.source` gets `"ner"`. `"presidio"`, `PresidioRecognizerResult` and `AnalyzeRequest` stay until Phase 4, since `presidio.ts` and `client.ts` still use them |
| `src/index.ts` | `PresidioUnavailableError` becomes `ModelLoadError`, still exit code 2 |
| `src/pii/layers/regex.ts` | Covers what only Presidio caught (see "Regex additions") |
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
  on the CPU (`onnxruntime-node`).
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
  (default 256, hard maximum 510, plus `[CLS]`/`[SEP]`).
- Consecutive windows overlap by 64 sub-tokens.
- A piece that appears in two windows takes the label from the window where
  it is further from a **cut** edge, since it has more context there. The
  start of the first window and the end of the last are the text's own ends,
  not cuts, so they don't count as edges.
- Windows run in padded batches of `NER_BATCH_SIZE` (default 8) with an
  `attention_mask`.
- A single piece longer than a window (a base64 blob, say) is labelled `O`.
  It is not a name, and regex still sees it.

Every piece gets exactly one label, so nothing past token 512 goes unread.
`ner.ts` checks this and throws if any piece was left unlabelled.

### 4. Labels to spans

Walk the labelled pieces in order:

- `B-X` starts a span of type X. `I-X` continues an open span of type X, or
  starts one if none is open (models do emit a stray `I-`).
- A span ends at `O`, at a change of type, or at a **line break** between two
  pieces. That keeps today's rule that names end at the first line break.
- A span's score is the mean of its pieces' scores; spans under
  `NER_MIN_SCORE` are dropped.
- Model labels are mapped to our `EntityType` by a per-model table in
  `ner.ts`. Labels not in the table (LOCATION, AGE, URL, …) are ignored.
  **ORGANIZATION is always ignored**: companies come only from the pre-defined
  list, as today.

### 5. Filters kept from `presidio.ts`

These are applied unchanged after grouping:

- `trimName`: cut a name at the first line break or word with a digit, and
  strip trailing punctuation
- `looksLikePerson`: drop names made only of English words unless one is a
  listed given name, and drop a lowercase name on a line that has capitals
- the IPv4 filter, if the chosen model emits PHONE_NUMBER

Phase 2 of PLAN.md re-checks that each filter still helps with the new model.
The lowercase-line rule was written for a cased model.

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `NER_MODEL` | set in Phase 2 | folder under `models/`, e.g. `gravitee-io/bert-small-pii-detection` |
| `NER_MIN_SCORE` | set in Phase 2 | spans below it are dropped |
| `NER_WINDOW_TOKENS` | `256` | at most 510 |
| `NER_BATCH_SIZE` | `8` | windows per model call |

`PRESIDIO_ANALYZER_URL` and `PRESIDIO_ANALYZER_WORKERS` go away.

## Model candidates

Checked on Hugging Face on 2026-09-30:

| Model | Licence | Quantized size | Cased | Labels we'd use | Notes |
| --- | --- | --- | --- | --- | --- |
| `gravitee-io/bert-small-pii-detection` | Apache-2.0 | 29 MB | **no** | PERSON, and possibly PHONE_NUMBER, US_PASSPORT, … | Try first. Uncased, so it may help with lowercase speech-to-text. Uses Presidio's type names. Its ONNX files are at the repo root (`model.quant.onnx`), so `fetch:model` moves them to `onnx/model_quantized.onnx` |
| `Xenova/bert-base-NER` | MIT | 109 MB | yes | PER | Closest to spaCy. Likely just as weak on lowercase text |
| `Xenova/distilbert-base-multilingual-cased-ner-hrl` | AFL-3.0 (upstream `Davlan/…`) | ~135 MB | yes | PER | Covers several languages including Arabic script |
| `bardsai/eu-pii-anonimization-multilang` | Apache-2.0 | 279 MB | yes | PERSON_NAME | XLM-R, multilingual, PII-specific. Large and slower |
| ~~`iiiorg/piiranha-v1-…`~~ | CC-BY-NC-ND-4.0 | — | — | — | **Excluded: licence forbids commercial use** |

## Regex additions

Only three values in the saved `reports/` came from Presidio and no other
layer. `regex.ts` has to cover them before Presidio is gone:

| Missed by regex | Example | Fix |
| --- | --- | --- |
| Phone numbers in single- or two-digit groups | `+33 6 12 34 56 78` | Validate `+`-prefixed candidates with `libphonenumber-js` |
| Passport with no keyword right before it | `"A38291049"` a few words after "passport" | US passport shape (`[A-Z]\d{8}` or 9 digits) when "passport" is on the same line |
| (Presidio behaviour we should copy) | `000-12-3456` | Skip impossible SSNs: area 000, 666 or 900–999, group 00, serial 0000 |

## Design rules (unchanged)

- **Offsets come from the original text.** Pieces are found by regex over the
  original text, and every span is checked against it.
- **Fail closed.** If the model is missing or won't load, or the input is over
  2,000,000 characters, the run stops with no output.
- **Merging favours masking.** When layers disagree about where a value ends,
  the union is masked.

## Found while building (Phase 1)

Measured with gravitee, `NER_MIN_SCORE` 0.5 (provisional), window 256,
batch 8, on a 16-thread Windows machine. Phase 2 tunes all of this.

- **The model sometimes tags each word of a name `B-`** ("kofi mensah" →
  `B-PERSON B-PERSON`; "sarah johnson" → `B-PERSON I-PERSON`). Grouping follows
  the rule above, so these become two adjacent spans. Nothing leaks, but the
  output reads `<PERSON_1> <PERSON_2>` where Presidio gave one placeholder.
  Phase 2 should decide whether adjacent same-type spans on one line are joined.
- **Initials can split around the dot.** In `mockup_interview.txt` "J.L.
  Picard" comes out as "J" and "L. Picard", leaving the "." visible.
- **Types other than PERSON cost precision.** Phase 1 takes every one of our
  types except ORGANIZATION, as Presidio was asked for. DATE_TIME alone adds
  153 false positives (times, durations, "today"), and US_SSN / US_PASSPORT
  tag keyword phrases ("US Passport number"). This is the PLAN.md 2.4 decision.
- **Speed is the model's own compute.** About 90% of the time on 229 KB is in
  `onnxruntime`'s `session.run`; tokenizing takes under 0.1 s. The 64-token
  overlap adds about a third more tokens at window 256.
