# PII Detection & Redaction Pipeline

English-language PII redaction for support transcripts, fully in-process: no
Docker, no service, no network at run time. Four detection layers —
pre-defined lists (yours, plus name registries), regex, a local NER model
(Transformers.js) and wink-nlp — each find values; their results are merged
and masked. How it works: [ARCHITECTURE.md](ARCHITECTURE.md). Known drawbacks:
[LIMITATIONS.md](LIMITATIONS.md).

## What gets redacted

`PERSON` (English names, and Arabic names written in English), `ORGANIZATION`
(only the companies you list, see below), `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `IBAN_CODE`, `DATE_TIME`,
`US_SSN`, `US_PASSPORT`, `US_DRIVER_LICENSE`.

Each value becomes a numbered placeholder, `<TYPE_N>`. Within one document the
same value always gets the same number. Different text is a different value,
so a first name used alone gets its own number:

```text
Hi, I'm Sarah Johnson. Card 4532 0151 1283 0366.  ->  Hi, I'm <PERSON_1>. Card <CREDIT_CARD_1>.
Thanks, Sarah. Bye, Sarah Johnson.                ->  Thanks, <PERSON_2>. Bye, <PERSON_1>.
```

Once a value is found, every other occurrence of it is masked too, and so is
each part of a found name ("Sarah" and "Johnson" alone after "Sarah Johnson").

Everything else (IP addresses, locations, street addresses, …) is left untouched
by design: the scope is `ENTITY_TYPES` in `src/pii/types.ts`.

## Pre-defined list

Values you always want masked, whatever the detectors think, go in
`config/predefined-list.json`, per type:

```json
{
  "PERSON": ["Sarah Johnson", "Kofi Mensah"],
  "ORGANIZATION": ["Exampleco Inc", "Acme Corp"],
  "EMAIL_ADDRESS": ["ops@acme.com"]
}
```

Matching is case-insensitive and whole-word. This is the most reliable way to
cover names you know in advance (customers, staff), especially in lowercase
speech-to-text, where names that are also English words ("will", "grace") are
easy to miss.

**Companies are masked only from this list.** Automatic company detection
mostly flagged products, acronyms and headings, so it is not used: a company
is masked if and only if it is listed here. Add your clients, partners and
your own company. An entry with a legal suffix also covers the short name:
`"Exampleco Inc"` masks "Exampleco" and "EXAMPLECO" too. The short name
matches only capitalised or in capitals, so the ordinary word "exampleco" is
left alone; list other short forms or abbreviations explicitly.

## Name lists

`data/lists/` holds ~130k given names, ~660k surnames and ~42k place names,
built from open registries. To refresh
them (needs internet, takes about a minute):

```bash
npm run build:lists
```

Sources: [Wikidata](https://www.wikidata.org) (CC0) via the
[QLever](https://qlever.dev) mirror, and [GeoNames](https://www.geonames.org) place
names, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
See ARCHITECTURE.md for how list entries are matched.

## NER model

Names are also found by
[`gravitee-io/bert-small-pii-detection`](https://huggingface.co/gravitee-io/bert-small-pii-detection)
(Apache-2.0, 29 MB quantized ONNX), run on the CPU through
[Transformers.js](https://huggingface.co/docs/transformers.js). Only its
PERSON labels are used. The model is **not** part of this repository:
`npm run fetch:model` downloads it once from Hugging Face into `models/`
(git-ignored), pinned to one revision and checked by SHA-256.

## Running it

```bash
npm install
npm run fetch:model            # once: the pinned NER model into models/ (needs internet)
npm run dev -- <file>          # writes reports/<name>__sanitized<ext>
```

After the fetch, runs need no network. The CLI writes only the **redacted**
text and never prints original values. Exit codes: 1 bad input, 2 NER model
missing or failed to load (run `npm run fetch:model`), 3 unexpected error. On
any error nothing is written.

## Checking a change

```bash
npm run typecheck
npm run check                  # redacts test_data/*.txt, compares with test_data/expected/
npm run check -- --update      # after reviewing a difference, save it as expected
npm run eval                   # recall, leaked characters and precision against test_data/labels/
npm run check:offsets          # every span equals its slice of the text (emoji, CRLF, windows, 229 KB)
```

There are no unit tests. `npm run check` fails (exit 1) on any difference and
shows the first changed line of each file. `npm run eval` scores the output
against hand-reviewed labels and compares it with the previous pipeline's
saved output (`test_data/reference/`); see ARCHITECTURE.md.

## Configuration

Read once at startup; `.env` is loaded and git-ignored.

| Variable | Default | Notes |
| --- | --- | --- |
| `NER_MODEL` | `gravitee-io/bert-small-pii-detection` | must be listed in `src/pii/layers/ner_models.ts` and fetched |
| `NER_MIN_SCORE` | `0.5` | name spans scored below it are dropped |
| `NER_WINDOW_TOKENS` | `384` | model window in sub-tokens, at most 510 |
| `NER_THREADS` | half the logical CPUs | onnxruntime threads |

## Library use

```ts
import { redact, detect } from "./src/pii/redact";

const { text, spans } = await redact(input);
```

`detect()` returns the spans only: absolute UTF-16 offsets, sorted and
non-overlapping. Inputs over 2,000,000 characters throw `InputTooLargeError`;
a missing or broken model throws `ModelLoadError`. The model loads on the
first call and is reused, so later calls in the same process are much faster.

## Measured numbers (2026-09-30)

On the 8 labelled files in `test_data/` (`npm run eval`):

| | This pipeline | Previous pipeline (spaCy NER) |
| --- | --- | --- |
| All PII found / characters leaked / precision | 99.2% / 0.4% / 98.4% | 98.7% / 0.7% / 94.2% |
| Names found / characters leaked / precision | 99.1% / 0.5% / 98.2% | 98.5% / 0.9% / 97.9% |
| Name characters leaked, lowercase speech-to-text | 10.8% | 24.3% |

The previous pipeline's figures are from its saved output on 7 of the files
(the 8th was added later). Every type other than PERSON is at 100% found and
100% precision. The set is small; see [LIMITATIONS.md](LIMITATIONS.md).

Speed on an 8-core laptop (median of 5; *cold* = the first call in a new
process, as in one CLI run, including loading the lists and the model; *warm*
= a later call in the same process, as in library use):

| Input | Cold | Warm |
| --- | --- | --- |
| 6 KB | 1.4 s | 0.19 s |
| 60 KB | 2.8 s | 1.6 s |
| 229 KB | 8.6 s | 7.0 s |

These were measured with other apps using ~30% of the CPU; large files vary
most (229 KB warm ranged 6.1–11.8 s, and took 5.2 s in quieter tuning runs).
`npm run dev` adds about 1.7 s of `npm` and `tsx` start-up on top of *cold*.
Peak memory is about 0.46 GB (6 KB) to about 0.5 GB (229 KB).
