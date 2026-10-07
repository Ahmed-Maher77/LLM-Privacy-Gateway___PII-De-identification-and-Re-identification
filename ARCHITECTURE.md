# How the pipeline works

English-only name and company redaction for support transcripts. Two
independent detection layers find values; an every-occurrence step and one
merge step combine them; every value is replaced with a numbered placeholder.
Everything runs in-process: no Docker, no service, no network at run time.
Nothing is stored: redaction is one-way.

```text
file ─▶ src/index.ts ─▶ redact() ─▶ detect()
                                      ├─ 1. pre-defined lists  layers/predefined.ts ──▶ config/desired- and undesired-predefined-list.json
                                      ├─ 2. NER model          layers/ner.ts ──▶ models/<model>/ (local ONNX)
                                      ├─ drop undesired model findings (layers/predefined.ts)
                                      ├─ every occurrence of a found value   post_processing/everyOccurrence.ts
                                      └─ merge overlaps                      post_processing/mergeSpans.ts
                         ─▶ Placeholders (placeholders.ts) ─▶ reports/<name>__sanitized<ext>
```

Source layout: `src/pii/` is the pipeline, `src/utils/` its helpers.

```text
src/
├─ index.ts                      CLI: reads the file, writes reports/, sets the exit code
├─ pii/
│  ├─ redact.ts                  public API: detect(), redact(); runs the steps in order
│  ├─ layers/predefined.ts       1. the desired and undesired lists
│  ├─ layers/ner.ts              2. the NER model
│  ├─ post_processing/           everyOccurrence.ts, mergeSpans.ts
│  ├─ placeholders.ts            <TYPE_N> numbering
│  ├─ generate_reports/          the sanitized text and the JSON report
│  └─ types.ts
└─ utils/
   ├─ envGetter.ts               typed .env reads
   ├─ ner_utils/                 model loading, pieces, windows, labels (ner_helpers.ts);
   │                             pinned models (ner_models.ts); the common-word list (vocabulary.ts)
   └─ predefinedLists_utils/     list loading (loadLists.ts), list rules (predefined_helpers.ts),
                                 word lists and regex helpers (text_helpers.ts)
```

On 2026-09-30 the pipeline was cut from four layers to two: the regex layer
(emails, phones, cards, IBANs, dates, SSNs, passports, driver's licences),
the wink-nlp layer (emails, natural-language dates) and the name registries
(~130k given names, ~660k surnames, ~42k places) were removed, with their
types.

## Types

PERSON and ORGANIZATION (`ENTITY_TYPES` in `types.ts`). Everything else passes
through.

## The layers

Each layer takes the original text and returns spans with offsets into it.
No layer depends on another.

| Layer               | Finds                                                      | How                                                                                                                                                                  |
| ------------------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Pre-defined lists | whatever you list, and the **only** source of ORGANIZATION; plus the words never to mask | `config/desired-predefined-list.json`, per type: `{ "PERSON": ["Sarah Johnson"], "ORGANIZATION": ["Acme Corp"] }`, whole entries and their parts; `config/undesired-predefined-list.json`, the correctives (next section). |
| 2. NER model        | names only                                                 | `gravitee-io/bert-small-pii-detection` through Transformers.js, on the CPU (section below).                                                                          |

## The pre-defined lists (`layers/predefined.ts`)

One layer, two files in `config/`, named in `.env` and read once per process
(each CLI run picks up edits; a long-running process needs a restart):

| File | `.env` variable | Content |
| --- | --- | --- |
| `desired-predefined-list.json` | `DESIRED_PREDEFINED_LIST` | names and companies to always mask, per type |
| `undesired-predefined-list.json` | `UNDESIRED_PREDEFINED_LIST` | words and phrases never to mask (correctives) |

A missing file, invalid JSON, an unknown type or a wrong shape stops the run
with a `ListError` (the CLI prints it and exits with code 2): running without
a list could leak the names on it.

### Desired list

- **Whole entries:** case-insensitive, whole words (no letter, digit or `_`
  on either side), any whitespace between words, including a line break.
- **Parts of a `PERSON` entry:** each word of a multi-word entry that is at
  least 2 letters and not a title, role, particle, filler or suffix ("Mr",
  "Agent", "al", "van", "Jr"): "Jean-Luc Picard" gives "Jean-Luc" and
  "Picard". A part matches capitalised ("Picard") or in capitals ("PICARD").
  Lowercase ("picard") it matches only on a line with no capital letters,
  i.e. speech-to-text, and only if it is not a common word (next section),
  so "Will Mensah" masks "Will" but not "i will".
- **Short company names:** an `ORGANIZATION` entry ending in a legal suffix
  (Inc, LLC, Ltd, Corp, GmbH, S.A.E, …) also matches without it, capitalised
  or in capitals: "Acme Corp" gives "Acme" and "ACME", not
  "acme".

Longer alternatives are tried first, so "Sarah Johnson" is one match, not two.

### Undesired list

An array of words and phrases never to mask, case-insensitive,
whitespace-normalised.

- **Model findings:** a span equal to an entry is dropped; entry words at its
  ends are trimmed, and the rest is dropped if it is an entry too
  (`removeUndesired()`, applied in `redact.ts` to the NER spans before
  every-occurrence, so a dropped value is never spread).
- **Desired list:** whole entries always win. Part matches that are entries
  are skipped.
- **Every occurrence:** a name part that is an entry is not spread.

## Common words (`utils/ner_utils/vocabulary.ts`)

With the name registries and wink-nlp gone, the pipeline's only English
lexicon is the NER model's own vocabulary: 30,522 WordPiece tokens in
`tokenizer.json`, read synchronously (no model load). A **common word** is a
whole token in it ("hope", "will", "agent", but also "sarah", "tom"; not
"kofi", "mensah", "okafor"). It is used in exactly two places, both for
**lowercase** words only: a lowercase part of a listed name, and a lowercase
value spread by every-occurrence. Capitalised words are never tested, so
common first names still work in normal text.

## The NER layer (`layers/ner.ts`)

### Model

[`gravitee-io/bert-small-pii-detection`](https://huggingface.co/gravitee-io/bert-small-pii-detection)
at revision `f8c27a8`: Apache-2.0, uncased BERT-small fine-tuned for PII, 29
MB quantized (q8) ONNX. It is fetched, not redistributed: `npm run
fetch:model` (`scripts/fetch-model.ts`) downloads the pinned files into
`models/` (git-ignored), checks each SHA-256, and moves the ONNX file from the
repo root to `onnx/model_quantized.onnx`, where Transformers.js looks.
`utils/ner_utils/ner_models.ts` holds each model's revision, files, hashes and the
label that means PERSON.

**Only PERSON is taken from the model.** Its other types are out of scope,
and ORGANIZATION would never be taken: companies come only from the
pre-defined list.

### Why not `pipeline("token-classification")`

In `@huggingface/transformers` 4.3.0 it gives no character offsets (`start` /
`end` are a `TODO`), and it tokenizes with `truncation: true`, so text past
512 tokens would never be looked at, a quiet leak. `ner.ts` calls
`AutoTokenizer` and `AutoModelForTokenClassification` directly and works out
offsets itself. The steps below are in `utils/ner_utils/ner_helpers.ts`;
`layers/ner.ts` runs them in order.

### 1. Loading (once per process)

- The package is an ES module; a static `import` from this CommonJS project
  fails `tsc` (TS1479), so values come from `await import(...)` and types from
  `import type … with { "resolution-mode": "import" }`.
- `env.allowRemoteModels = false`: nothing is ever downloaded at run time.
- The model loads on the first call and the promise is reused.
- q8 weights on the CPU (`onnxruntime-node`, its native binary is bundled).
  fp32 was slower and 4× larger.
- onnxruntime's intra-op threads are fixed at half the logical CPUs (one per
  physical core with hyper-threading; not configurable). Its own default
  ran about as fast as 2 threads on an 8-core / 16-thread machine.
- `[CLS]` / `[SEP]` come from `tokenizer.encode("")` (`cls_token_id` is
  `undefined` in 4.3.0). The model takes `input_ids` and `attention_mask`
  only.
- A missing or broken model throws `ModelLoadError` ("Run `npm run
  fetch:model`"); the CLI exits with code 2 and writes nothing.

### 2. Pieces: offsets come from our own split

The text is split by `/[^\s\p{P}\p{S}]+|[\p{P}\p{S}]/gu` into **pieces**
(runs of letters/digits, or one punctuation mark or symbol), each with its
UTF-16 `start` / `end`. This is close to BERT's own pre-tokenizer; BERT keeps
non-ASCII symbols such as emoji attached to the next word, where we split
them off, which never splits a name. Each piece is tokenized on its own and
cached by string. A piece that tokenizes to nothing (a lone zero-width
character) is skipped. A piece's label is its **first sub-token's** label,
with that sub-token's softmax probability as the score.

The model never gives offsets: a span's offsets are its pieces' offsets, and
before returning, every span is checked to equal `text.slice(start, end)`.

### 3. Windows: no truncation

- Pieces are packed into windows of at most `NER_WINDOW_TOKENS` sub-tokens
  (default 384, at most 510, plus `[CLS]` / `[SEP]`), overlapping by
  `NER_OVERLAP_TOKENS` (default 32).
- A piece seen in two windows keeps the label from the one where it is
  further from a **cut** edge (the text's own start and end are not cuts).
- One window per model call, no padding: batching was slower on the CPU.
- A piece longer than a window (a base64 blob) is labelled `O`: no name is
  that long.
- `ner.ts` throws if any piece was left unlabelled.

### 4. Labels to name spans

- `B-PERSON` starts a span, `I-PERSON` continues one (or starts one after a
  stray `I-`).
- A span is made of letter pieces and may continue across the joiners
  `.` `'` `’` `-` ("Al-Rashid", "L. Picard"); anything else ends it: `O`, other
  punctuation, a piece with a digit, a line break. It never ends on a joiner.
- Its score is the mean of its letter pieces' scores.
- **Adjacent spans are joined** when they are on one line and separated only
  by spaces/tabs or a single `.`. The model often tags each word of a name
  `B-` ("kofi mensah"); joined, the name gets one placeholder and initials
  leave nothing visible ("J" + "." + "L. Picard"). A joined span takes its
  stronger part's score.
- Spans under `NER_MIN_SCORE` (0.5) are dropped **after** joining, so a name
  is kept or dropped whole: a surname scored 0.49 next to a first name scored
  0.94 stays masked.

### 5. Filters (word lists in `utils/predefinedLists_utils/text_helpers.ts`)

- **Edges:** `TITLES` and `NEVER_NAMES` are trimmed at both ends. `TITLES`
  are titles ("Mr", "Dr.", "doctor"), roles ("Agent", "customer", "rep") and
  relations ("wife", "brother"): "Agent David" → "David", "my wife mariam" →
  "mariam". `NEVER_NAMES` are greetings and fillers ("hi", "yep", "perfect",
  "Salam"). Words before a title inside the span are dropped ("thank you
  mister el sayed" → "el sayed"; a title at the very end doesn't count). A
  span with nothing left is dropped ("Mr", "Salam"). This matters because the
  every-occurrence step masks each capitalised part of a name everywhere:
  untrimmed, "Agent" and "Customer" were masked on every line (21 false
  positives in `test_5.txt` alone).
- **Acronyms:** a span made only of all-caps words ("FHIR", "AA") is dropped,
  unless the rest of its line is in capitals too.
- **Case:** a lowercase span on a line that has capitals is dropped.

### How the settings were chosen (2026-09-30)

- **Threshold:** 0.1–0.5 scored the same on the labelled set; 0.6 also dropped
  one false positive; 0.7 lost a name (×11 through every-occurrence). 0.5
  keeps a margin.
- **PERSON false positives** went from 30 (all types taken, no filters) to 5
  with the edge trim, `NEVER_NAMES` and acronym filters, 6 at window 384,
  and 5 once one-word English names stopped spreading ("grace period").
- **Speed**, 229 KB warm, 8-core / 16-thread laptop, all in one tuning
  session (latency under everyday load is in LIMITATIONS.md):

    | Setting                                                       | 229 KB warm                     |
    | ------------------------------------------------------------- | ------------------------------- |
    | q8, window 256/64, batch 8, onnxruntime's default threads     | 10.2 s                          |
    | fp32 (default / 8 threads)                                    | 11.5 / 9.5 s                    |
    | q8, threads 1 / 2 / 4 / 8 / 16                                | 31.4 / 11.1 / 7.5 / 6.6 / 8.7 s |
    | q8, 8 threads, window 384 or 510 (overlap 32), batch 8        | 6.8 / 7.9 s                     |
    | q8, 8 threads, window 384, batch 1 / 2 / 4                    | 5.5 / 5.7 / 6.3 s               |
    | **Chosen: q8, window 384/32, one window per call, 8 threads** | **5.2 s**                       |

    About 90% of the time is onnxruntime's own compute (58,436 sub-tokens for
    229 KB), which sets the floor.

- **Two layers (2026-09-30).** The 4-layer pipeline trimmed any leading
  English word that wasn't a listed given name; without the registries, that
  rule became the role and filler words in `TITLES` / `NEVER_NAMES`, which
  took false positives from 31 back to 7. `NER_MIN_SCORE` 0.3 and 0.4 were
  re-tried: they add 2 false positives ("Support") and recover none of the
  names only the registries had found. 0.5 stays.
- **`Xenova/bert-base-NER`** (MIT, cased, 109 MB) was scored with the same
  filters and rejected: more name characters leaked in lowercase text (24.3%,
  no better than the old pipeline), 11 false positives, 17 s for 229 KB.

## After the layers (`post_processing/`, run by `redact.ts`)

1. **Every occurrence.** A value found once is masked everywhere in the
   document, and each part of a found name too: after "Sarah Chen", also
   "Sarah" and "Chen" alone (parts of 3+ letters; titles and roles like "Mr"
   excluded). A model often finds a name only some of the times it appears.
   Undesired words are not spread either. A lowercase common word
   (`utils/ner_utils/vocabulary.ts`) is not spread, whether it is a
   whole found value or a part of one: a found "hope" or "bill" leaves "i
   hope" and "phone bill" alone.
2. **Merge.** Overlapping spans become one span covering all of them, so
   nothing a layer found stays partly visible. It takes the type of the
   longest piece.
3. **Placeholders** (`placeholders.ts`). Each span becomes `<TYPE_N>`. The same
   value (ignoring case, spaces, dots, hyphens and a trailing "'s") gets the
   same N within a document. "Sarah Chen" and "Sarah" are
   different values.

## Design rules

- **Offsets come from the original text.** List matches and NER pieces are
  found by regex over the original text; the NER layer fails the run if a
  span doesn't match the text.
- **Fail closed.** If the model or a list file is missing or won't load, a
  setting in `.env` is invalid, or input is over 2,000,000 characters, the
  run stops with no output.
- **No truncation.** Every piece of the input is seen by the model; a gap
  fails the run.
- **Merging favours masking.** When layers disagree about where a value ends,
  the union is masked.
