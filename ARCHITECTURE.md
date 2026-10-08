# How the pipeline works

English-only PII redaction for support transcripts. Four independent
detection layers find values; one merge step combines them; every value is
replaced with a numbered placeholder. Everything runs in-process: no Docker,
no service, no network at run time. Redaction is one-way: no mapping back is
kept (the CLI's JSON report does list each detected value, see LIMITATIONS.md).

```text
file ─▶ src/index.ts ─▶ redact() ─▶ detect()
                                      ├─ 1. pre-defined list   layers/predefined.ts
                                      │     name lists         layers/dictionary.ts  (data/lists/)
                                      ├─ 2. regex              layers/regex.ts
                                      ├─ 3. NER model          layers/ner.ts ──▶ models/<model>/ (local ONNX)
                                      ├─ 4. wink-nlp           layers/wink.ts
                                      ├─ every occurrence of a found value
                                      └─ merge overlaps
                         ─▶ Placeholders (policy.ts) ─▶ reports/<name>__sanitized<ext> + reports/<name>__report.json
```

The NER layer replaced a Presidio (spaCy) sidecar on 2026-09-30; the old
pipeline's saved output is kept in `test_data/reference/` for comparison.

## Types

PERSON, ORGANIZATION, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, IBAN_CODE,
DATE_TIME, US_SSN, US_PASSPORT, US_DRIVER_LICENSE (`ENTITY_TYPES` in `types.ts`).
Everything else passes through.

## The layers

Each layer takes the original text and returns spans with offsets into it.
No layer depends on another.

| Layer | Finds | How |
| --- | --- | --- |
| 1. Pre-defined list | whatever you list, and the **only** source of ORGANIZATION | `config/predefined-list.json`, per type: `{ "PERSON": ["Sarah Johnson"], "ORGANIZATION": ["Acme Corp"] }`. Case-insensitive, whole words. |
| 1b. Name lists | names (English, and Arabic written in English) | Registry lists in `data/lists/` (next section), each hit checked by a rule so list entries that are also English words ("Will", "Grace") don't match on their own. |
| 2. Regex | emails, cards, IBANs, SSNs, passports, driver's licences, phones, dates | Fixed formats. Cards must pass Luhn, IBANs mod-97, `+`-prefixed international phones `libphonenumber-js`. SSNs in impossible ranges are skipped. Passports and licences need a keyword first ("passport number is …"); a US passport shape (letter + 8 digits, or 9 digits) is also taken anywhere on a line that says "passport". |
| 3. NER model | names only | `gravitee-io/bert-small-pii-detection` through Transformers.js, on the CPU (section below). |
| 4. wink-nlp | emails, natural-language dates | A date must contain a digit, or a month name plus another word ("today" is not PII). |

## Name lists (`data/lists/`, `layers/dictionary.ts`)

Built from open registries by `npm run build:lists` (`scripts/build-lists.ts`);
the files are kept in the repo so the pipeline never needs the network.

| File | Entries | Source |
| --- | --- | --- |
| `given-names.txt` | ~130k | Wikidata given names: labels and English aliases, so spelling variants are in (Mohamed / Mohammed / Muhammad) |
| `surnames.txt` | ~660k | Wikidata family names |
| `places.txt` | ~42k | GeoNames cities (pop. ≥ 15,000), regions, countries; used only so "Austin" or "Sydney" is not read as a first name |

A list hit must also pass a rule:

- **Full name:** 2–6 words (particles included) starting with a capitalised given name, each next
  capitalised word a given name, a surname or not an English word, with at least one word
  that isn't English: "Mohamed Ahmed Hassan", "Kofi Mensah". Particles are
  allowed ("Abdel Rahman El-Hamed", "van Dijk"), and fused ones are stripped
  for the lookup ("Elsharif", "Al-Rashid"). Not a place ("New York"), not
  starting or ending with a place or organisation word ("Rue de la Paix",
  "Lincoln Street", "Grace Hopper Lab"), not ending in a code ("Houston TX").
- **Single name:** a given name that is neither an English word (wink's
  lexicon), a place, a filler or a common Arabic expression ("Uhh",
  "Salam", "inshallah"), nor a word with an inner capital ("IDs"): "Youssef", "Priya". Lowercase ("kofi") only on an
  all-lowercase line, i.e. speech-to-text.

## The NER layer (`layers/ner.ts`)

### Model

[`gravitee-io/bert-small-pii-detection`](https://huggingface.co/gravitee-io/bert-small-pii-detection)
at revision `f8c27a8`: Apache-2.0, uncased BERT-small fine-tuned for PII, 29
MB quantized (q8) ONNX. It is fetched, not redistributed: `npm run
fetch:model` (`scripts/fetch-model.ts`) downloads the pinned files into
`models/` (git-ignored), checks each SHA-256, and moves the ONNX file from the
repo root to `onnx/model_quantized.onnx`, where Transformers.js looks.
`layers/ner_models.ts` holds each model's revision, files, hashes and the
label that means PERSON.

**Only PERSON is taken from the model.** Regex covers every other type with
100% recall on the labelled set, and the model's other types cost precision:
its DATE_TIME alone added 153 false positives (times, durations, "today"),
and its SSN / passport labels landed on keyword phrases. ORGANIZATION would
never be taken: companies come only from the pre-defined list.

### Why not `pipeline("token-classification")`

In `@huggingface/transformers` 4.3.0 it gives no character offsets (`start` /
`end` are a `TODO`), and it tokenizes with `truncation: true`, so text past
512 tokens would never be looked at, a quiet leak. `ner.ts` calls
`AutoTokenizer` and `AutoModelForTokenClassification` directly and works out
offsets itself.

### 1. Loading (once per process)

- The package is an ES module; a static `import` from this CommonJS project
  fails `tsc` (TS1479), so values come from `await import(...)` and types from
  `import type … with { "resolution-mode": "import" }`.
- `env.allowRemoteModels = false`: nothing is ever downloaded at run time.
- The model loads on the first call and the promise is reused.
- q8 weights on the CPU (`onnxruntime-node`, its native binary is bundled).
  fp32 was slower and 4× larger.
- onnxruntime's intra-op threads are set to `NER_THREADS` (default: half the
  logical CPUs, one per physical core with hyper-threading). Its own default
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
  (default 384, at most 510, plus `[CLS]` / `[SEP]`), overlapping by 32.
- A piece seen in two windows keeps the label from the one where it is
  further from a **cut** edge (the text's own start and end are not cuts).
- One window per model call, no padding: batching was slower on the CPU.
- A piece longer than a window (a base64 blob) is labelled `O`; regex still
  sees it.
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

### 5. Filters (reusing `dictionary_helpers.ts`)

- **Edges:** titles (`TITLES`: "Mr", "Dr.", "doctor") and `NEVER_NAMES`
  (greetings and fillers: "hi", "bye", "thanks", "Salam") are trimmed at both
  ends, and leading words that are English words but not listed given names
  at the start ("Agent David" → "David"). Ordinary English words are not
  trimmed at the end: a surname could be one. Words before a title inside
  the span are dropped ("thank you mister el hamed" → "el hamed"; a title at
  the very end doesn't count). A span with nothing left is dropped ("Mr",
  "Salam"). This matters because the every-occurrence step
  masks each capitalised part of a name everywhere: untrimmed, "Agent" was
  masked on every line. The name lists apply the same rule: a `NEVER_NAMES`
  word never becomes part of a name ("youssef salam").
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

  | Setting | 229 KB warm |
  | --- | --- |
  | q8, window 256/64, batch 8, onnxruntime's default threads | 10.2 s |
  | fp32 (default / 8 threads) | 11.5 / 9.5 s |
  | q8, threads 1 / 2 / 4 / 8 / 16 | 31.4 / 11.1 / 7.5 / 6.6 / 8.7 s |
  | q8, 8 threads, window 384 or 510 (overlap 32), batch 8 | 6.8 / 7.9 s |
  | q8, 8 threads, window 384, batch 1 / 2 / 4 | 5.5 / 5.7 / 6.3 s |
  | **Chosen: q8, window 384/32, one window per call, 8 threads** | **5.2 s** |

  About 90% of the time is onnxruntime's own compute (58,436 sub-tokens for
  229 KB), which sets the floor.
- **`Xenova/bert-base-NER`** (MIT, cased, 109 MB) was scored with the same
  filters and rejected: more name characters leaked in lowercase text (24.3%,
  no better than the old pipeline), 11 false positives, 17 s for 229 KB.

## After the layers (`redact.ts`)

1. **Every occurrence.** A value found once is masked everywhere in the
   document, and each part of a found name too: after "Sarah Chen", also
   "Sarah" and "Chen" alone (titles like "Mr" excluded). A model often finds
   a name only some of the times it appears. A lowercase English word is not
   spread, whether it is a whole found value or a part of one: a found "hope"
   or "bill" leaves "i hope" and "phone bill" alone.
2. **Merge.** Overlapping spans become one span covering all of them, so
   nothing a layer found stays partly visible. It takes the type of the
   longest piece.
3. **Placeholders** (`policy.ts`). Each span becomes `<TYPE_N>`. The same
   value (ignoring case and separators; digits only for cards, phones and
   SSNs) gets the same N within a document. "Sarah Chen" and "Sarah" are
   different values.

## Design rules

- **Offsets come from the original text.** NER pieces are found by regex over
  the original text; wink offsets are rebuilt from its tokens. Both layers
  fail the run if a span doesn't match the text.
- **Fail closed.** If the model is missing or won't load, or input is over
  2,000,000 characters, the run stops with no output.
- **No truncation.** Every piece of the input is seen by the model; a gap
  fails the run.
- **Merging favours masking.** When layers disagree about where a value ends,
  the union is masked.

## Checking a change

There are no unit tests. Four commands, plus `npm run bench` for speed and
memory (cold and warm, 6 / 60 / 229 KB, median of 5 fresh processes):

| Command | What it checks |
| --- | --- |
| `npm run typecheck` | TypeScript |
| `npm run check` | redacts every `test_data/*.txt` and compares with `test_data/expected/`; after an intended change, review the diff, then `npm run check -- --update` |
| `npm run eval` | per file and type: recall (labelled values fully masked), leaked characters, over-masked characters (masked but in no label), precision, against `test_data/labels/`; then the totals against the old pipeline's saved output in `test_data/reference/`, and the name criteria. `--details` lists misses, false positives and over-masked spans (test data only); `--reference` scores the saved output alone |
| `npm run check:offsets` | every NER and pipeline span equals its slice of the text, on emoji and other non-BMP text, CRLF, a name at 300 positions across the window edge, and 229 KB |

Labels (`test_data/labels/<name>.json`) list the PII values per type. An entry
is a string (every whole-word, case-sensitive occurrence) or
`{ "value", "in"?, "hard"? }`: `in` limits it to occurrences inside that
context ("will" only in "my brother will might"), and `hard` keeps it out of
the headline numbers (spelled-out and spoken forms, Arabic script,
checksum-failing numbers). `"ignore": [...]` lists ambiguous words: a
detection over one counts as neither a hit nor a false positive. A value that
must stay visible (an impossible SSN in `regex_edge.txt`) is simply left
unlabelled, so masking it would show as a false positive.
