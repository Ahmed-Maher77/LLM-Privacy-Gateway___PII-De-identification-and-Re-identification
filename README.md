# Multi-layer PII Redaction (TypeScript)

English-language PII redaction for support transcripts, fully in-process: no
Docker, no service and no network at run time. Four independent detection
layers (pre-defined lists plus open name registries, regular expressions, a
local NER model run through Transformers.js, and wink-nlp) each find values;
their results are merged and every value is replaced with a numbered
placeholder such as `<PERSON_1>`. Redaction is one-way.

Part of the [PII de-identification implementations](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification#readme) collection.

## At a glance

| | |
| --- | --- |
| Language/runtime | TypeScript on Node.js 20.9 or later, run with `tsx`; npm |
| Approach | Pre-defined list and name registries, regex with checksums, NER model (`gravitee-io/bert-small-pii-detection`, ONNX on CPU), wink-nlp; overlapping results merged, every occurrence masked |
| Entities | `PERSON`, `ORGANIZATION` (listed companies only), `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `IBAN_CODE`, `DATE_TIME`, `US_SSN`, `US_PASSPORT`, `US_DRIVER_LICENSE` |
| Reversible | No: numbered placeholders, no mapping back is kept |
| Network at runtime | None. Needed once for `npm install` and `npm run fetch:model` |
| Models & data | NER model 29 MB (fetched, pinned, SHA-256-checked, not in the repository); name and place lists 7.1 MB (committed); `node_modules` about 530 MB |
| Best for | English support-call and chat transcripts, including lowercase speech-to-text, redacted on one machine without external services |
| Status | Working CLI and library with regression, accuracy and offset checks; evaluated on a small synthetic set; no HTTP API |

## Contents

- [Quick start](#quick-start)
- [Usage](#usage)
  - [Command line](#command-line)
  - [Library](#library)
  - [Configuration](#configuration)
  - [Pre-defined list](#pre-defined-list)
- [What gets redacted](#what-gets-redacted)
- [How it works](#how-it-works)
- [NER model](#ner-model)
- [Name lists](#name-lists)
- [Measured numbers](#measured-numbers)
- [Speed and memory](#speed-and-memory)
- [Checking a change](#checking-a-change)
- [Limitations](#limitations)
- [License](#license)

## Quick start

### Prerequisites

- Node.js 20.9 or later (a transitive dependency, `sharp`, requires it) and npm
- Internet access for the two set-up steps below; none afterwards

### Installation

```bash
npm install
npm run fetch:model            # once: the pinned NER model into models/ (about 29 MB)
```

### First run

```bash
npm run dev -- test_data/test_2.txt
```

This writes `reports/test_2__sanitized.txt` (the redacted text) and
`reports/test_2__report.json`. The console shows only the character count,
the time and the output paths.

## Usage

### Command line

```bash
npm run dev -- <file>          # writes reports/<name>__sanitized<ext> and reports/<name>__report.json
```

- The CLI never prints original values. The sanitized file holds the
  **redacted** text. `reports/<name>__report.json` holds timings and counts
  per layer, and every detected span **with its original value** in plain
  text (with type, score and source layer), for review. Keep `reports/`
  (git-ignored) as private as the input.
- Exit codes: `1` bad input (no file given, file not found, input over
  2,000,000 characters), `2` NER model missing or failed to load (run
  `npm run fetch:model`), `3` unexpected error. When detection fails, nothing
  is written.
- `npm run dev` adds about 1.7 s of `npm` and `tsx` start-up to each run.

All scripts:

| Script | Purpose |
| --- | --- |
| `npm run dev -- <file>` | Redact one file (above) |
| `npm run fetch:model` | Download the pinned NER model into `models/` (needs internet) |
| `npm run build:lists` | Rebuild the name and place lists in `data/lists/` (needs internet) |
| `npm run typecheck` | TypeScript check (`tsc --noEmit`) |
| `npm run check` | Regression check against `test_data/expected/` (see [Checking a change](#checking-a-change)) |
| `npm run eval` | Accuracy against hand-reviewed labels |
| `npm run check:offsets` | Span offset integrity on difficult inputs |
| `npm run bench` | Speed and memory on the current machine |

### Library

```ts
import "dotenv/config"; // only if settings come from .env; they are read at import
import { redact, detect, InputTooLargeError } from "./src/pii/redact";
import { ModelLoadError } from "./src/pii/layers/ner";

async function main() {
  const { text, spans, metrics } = await redact("Hi, I'm Sarah Johnson. Card 4532 0151 1283 0366.");
  // text: "Hi, I'm <PERSON_1>. Card <CREDIT_CARD_1>."
}
```

- `redact(text)` returns the redacted text, the spans and per-layer timings
  and counts. `detect(text)` returns the spans only.
- A span is `{ start, end, type, text, score?, source }` with absolute UTF-16
  offsets into the input; spans are sorted and non-overlapping.
- Inputs over 2,000,000 characters throw `InputTooLargeError`; a missing or
  broken model throws `ModelLoadError` (exported from `src/pii/layers/ner.ts`).
- The model and the lists load on the first call and are reused, so later
  calls in the same process are much faster.
- The library writes no files.

### Configuration

Settings are read once, when the NER layer is first imported. The CLI and the
scripts load `.env` (git-ignored); `.env.example` is a template.

| Variable | Default | Notes |
| --- | --- | --- |
| `NER_MODEL` | `gravitee-io/bert-small-pii-detection` | Must be listed in `src/pii/layers/ner_models.ts` and fetched |
| `NER_MIN_SCORE` | `0.5` | Name spans scored below it are dropped |
| `NER_WINDOW_TOKENS` | `384` | Model window in sub-tokens; capped at 510 |
| `NER_THREADS` | Half the logical CPUs | onnxruntime threads |

Numeric settings must be positive numbers; an invalid value stops the run at
start-up.

### Pre-defined list

Values you always want masked, whatever the detectors think, go in
`config/predefined-list.json`, per type. Keys must be entity types from the
list below.

```json
{
  "PERSON": ["Sarah Johnson", "Kofi Mensah"],
  "ORGANIZATION": ["Acme Corp", "Example Ltd"],
  "EMAIL_ADDRESS": ["ops@example.com"]
}
```

- Matching is case-insensitive and whole-word; longer entries win over
  shorter ones. A file saved with a byte-order mark is accepted.
- This is the most reliable way to cover names you know in advance
  (customers, staff), especially in lowercase speech-to-text, where names
  that are also English words ("will", "grace") are easy to miss.
- **Companies are masked only from this list.** Automatic company detection
  mostly flagged products, acronyms and headings, so it is not used: a
  company is masked if and only if it is listed here. Add your clients,
  partners and your own company.
- An entry with a legal suffix also covers the short name: `"Acme Corp"`
  masks "Acme" and "ACME" too. The short name matches only as written in the
  list or in capitals; list other short forms and abbreviations explicitly.

## What gets redacted

`PERSON` (English names, and Arabic names written in English),
`ORGANIZATION` (only the companies you list), `EMAIL_ADDRESS`,
`PHONE_NUMBER`, `CREDIT_CARD`, `IBAN_CODE`, `DATE_TIME`, `US_SSN`,
`US_PASSPORT`, `US_DRIVER_LICENSE`.

Each value becomes a numbered placeholder, `<TYPE_N>`. Within one document
the same value always gets the same number. Different text is a different
value, so a first name used alone gets its own number:

```text
Hi, I'm Sarah Johnson. Card 4532 0151 1283 0366.  ->  Hi, I'm <PERSON_1>. Card <CREDIT_CARD_1>.
Thanks, Sarah. Bye, Sarah Johnson.                ->  Thanks, <PERSON_2>. Bye, <PERSON_1>.
```

Once a value is found, every other occurrence of it is masked too, and so is
each part of a found name ("Sarah" and "Johnson" alone after "Sarah
Johnson"). Lowercase English words are not spread this way: after the name
"hope" in a speech-to-text transcript, "i hope" stays as it is.

Everything else (IP addresses, locations, street addresses, URLs, account
numbers, non-US IDs, ...) is left untouched by design: the scope is
`ENTITY_TYPES` in `src/pii/types.ts`.

## How it works

```text
file -> src/index.ts -> redact() -> detect()
                                      |- 1. pre-defined list + name lists
                                      |- 2. regex (Luhn, mod-97, libphonenumber-js checks)
                                      |- 3. NER model (local ONNX, PERSON only)
                                      |- 4. wink-nlp (emails, natural-language dates)
                                      |- every occurrence of a found value
                                      '- merge overlaps (union is masked)
                         -> numbered placeholders -> reports/
```

Each layer reads the original text and returns spans with offsets into it.
The pipeline fails closed: a missing model, oversized input or any span whose
offsets do not match the text stops the run with no output, and the model
sees every part of the input (no truncation). Details, design choices and
tuning measurements: [ARCHITECTURE.md](ARCHITECTURE.md).

## NER model

Names are also found by
[`gravitee-io/bert-small-pii-detection`](https://huggingface.co/gravitee-io/bert-small-pii-detection)
(Apache-2.0, uncased BERT-small, 29 MB quantized ONNX), run on the CPU
through [Transformers.js](https://huggingface.co/docs/transformers.js). Only
its PERSON labels are used. The model is **not** part of this repository:
`npm run fetch:model` downloads it once from Hugging Face into `models/`
(git-ignored), pinned to revision `f8c27a8` and checked by SHA-256. At run
time remote model loading is disabled.

## Name lists

`data/lists/` holds about 130k given names, 660k surnames and 42k place
names (built 2026-09-29) from open registries. The files are committed, so
the pipeline never needs the network. To refresh them (needs internet, takes
about a minute):

```bash
npm run build:lists
```

| File | Entries | Source |
| --- | --- | --- |
| `given-names.txt` | 130,456 | Wikidata given names, labels and English aliases (CC0) |
| `surnames.txt` | 661,089 | Wikidata family names (CC0) |
| `places.txt` | 41,938 | GeoNames cities (population 15,000 or more), regions and countries (CC BY 4.0); used only so "Austin" or "Sydney" is not read as a first name |

Wikidata is queried through the [QLever](https://qlever.dev) mirror;
[GeoNames](https://www.geonames.org) data is licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). See
[ARCHITECTURE.md](ARCHITECTURE.md) for how list entries are matched.

## Measured numbers

Measured 2026-10-07 with `npm run eval` on the labelled files in
`test_data/`. Against the previous pipeline (Presidio with spaCy NER), on the
6 files it has saved output for:

| | This pipeline | Previous pipeline (spaCy NER) |
| --- | --- | --- |
| All PII found / characters leaked / precision | 99.0% / 0.5% / 98.3% | 98.3% / 0.9% / 92.8% |
| Names found / characters leaked / precision | 98.8% / 0.7% / 98.1% | 98.1% / 1.3% / 97.3% |
| Name characters leaked, lowercase speech-to-text | 10.8% | 24.3% |

On all 10 files: 99.1% of PII found, 0.4% of characters leaked, 98.6%
precision. On the 4 lowercase speech-to-text files alone: 95.1% of names
found, 2.8% of name characters leaked, 100% name precision. Every type other
than `PERSON` is at 100% found and 100% precision. The set is small and
synthetic; see [LIMITATIONS.md](LIMITATIONS.md).

## Speed and memory

Measured 2026-09-30 on an 8-core laptop, median of 5. *Cold* is the first
call in a new process, as in one CLI run, including loading the lists and
the model; *warm* is a later call in the same process, as in library use.

| Input | Cold | Warm | Peak memory |
| --- | --- | --- | --- |
| 6 KB | 1.4 s | 0.19 s | 0.45 GB |
| 60 KB | 2.8 s | 1.6 s | 0.46 GB |
| 229 KB | 8.6 s | 7.0 s | 0.49 GB |

These figures were measured with other applications using about 30% of the
CPU, and the model's threads compete with them: large files vary most (229 KB
warm ranged 6.1–11.8 s, and took 5.2 s in quieter tuning runs). `npm run dev`
adds about 1.7 s of start-up on top of *cold*.

`npm run bench` measures this table on the machine it runs on (text built
from `test_data/`, a fresh process per run, about 3 minutes); run it on the
production machine.

## Checking a change

There are no unit tests. These commands cover a change:

```bash
npm run typecheck
npm run check                  # redacts test_data/*.txt, compares with test_data/expected/
npm run check -- --update      # after reviewing a difference, save it as expected
npm run eval                   # recall, leaked and over-masked characters, precision vs test_data/labels/
npm run eval -- --details      # also list misses, false positives and over-masked spans
npm run check:offsets          # every span equals its slice of the text (emoji, CRLF, window edges, 229 KB)
```

`npm run check` fails (exit 1) on any difference and shows the first changed
line of each file. `npm run eval` scores the output against hand-reviewed
labels and compares it with the previous pipeline's saved output
(`test_data/reference/`). The label format and the meaning of each metric
are described in [ARCHITECTURE.md](ARCHITECTURE.md#checking-a-change).

## Limitations

- English only; Arabic script and other languages get little or no name
  detection.
- Lowercase speech-to-text is the weak spot: names that are also English
  words ("will") can leak. Spelled-out names and spoken numbers, dates and
  emails are not detected.
- Companies are masked only when listed; addresses, locations, URLs, IP
  addresses, account numbers and non-US IDs are not masked.
- The every-occurrence rule can over-mask (after "Grace Hopper", every
  "Grace").
- Accuracy was measured on 10 small synthetic transcripts; real transcripts
  may do worse.
- The JSON report stores detected values in plain text.

Full list with examples and rule trade-offs: [LIMITATIONS.md](LIMITATIONS.md).

## License

Code: MIT, see [LICENSE](LICENSE). The name and place lists in `data/lists/`
keep their source licenses (Wikidata CC0, GeoNames CC BY 4.0). The NER model
(Apache-2.0) is downloaded from Hugging Face and not redistributed here.
