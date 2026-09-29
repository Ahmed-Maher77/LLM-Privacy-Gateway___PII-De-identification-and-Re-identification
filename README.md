# PII Detection & Redaction Pipeline

English-language PII redaction for support transcripts. Four detection
layers — pre-defined lists (yours, plus name registries), regex,
Presidio (spaCy NER) and wink-nlp — each find values; their results are
merged and masked. How it works:
[ARCHITECTURE.md](ARCHITECTURE.md). Known drawbacks: [LIMITATIONS.md](LIMITATIONS.md).

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
speech-to-text, where spaCy misses many names.

**Companies are masked only from this list.** Automatic company detection
(spaCy, company-name patterns, company registries) mostly flagged products,
acronyms and headings, so it was removed: a company is masked if and only if
it is listed here. Add your clients, partners and your own company. An entry
with a legal suffix also covers the short name: `"Exampleco Inc"` masks
"Exampleco" and "EXAMPLECO" too. The short name matches only capitalised or
in capitals, so the ordinary word "exampleco" is left alone; list other
short forms or abbreviations explicitly.

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

## Running it

```bash
npm install
npm run presidio:up            # analyzer on :5002 (pinned image)
npm run dev -- <file>          # writes reports/<name>__sanitized<ext>
npm run presidio:down
```

The CLI writes only the **redacted** text and never prints original values.
Exit codes: 1 bad input, 2 Presidio down, 3 unexpected error.

## Checking a change

```bash
npm run typecheck
npm run check                  # redacts test_data/*.txt, compares with test_data/expected/
npm run check -- --update      # after reviewing a difference, save it as expected
```

There are no unit tests. `npm run check` fails (exit 1) on any difference and
shows the first changed line of each file, so a rule change that starts leaking
a name shows up immediately. It needs Presidio running.

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `PRESIDIO_ANALYZER_URL` | `http://localhost:5002` | read once at startup; `.env` is loaded and git-ignored |
| `PRESIDIO_ANALYZER_WORKERS` | `4` | Docker Compose only; ~0.8 GB per worker |

## Library use

```ts
import { redact, detect } from "./src/pii/redact";

const { text, spans } = await redact(input);
```

`detect()` returns the spans only: absolute UTF-16 offsets, sorted and
non-overlapping. Inputs over 2,000,000 characters throw `InputTooLargeError`;
an unreachable analyzer throws `PresidioUnavailableError`.

## Last measured numbers (2026-09-29)

On 8 synthetic held-out documents: 96.7% of all PII found, 96.4% of names,
1.9% of name characters leaked. Lowercase speech-to-text is much weaker (about
37% of name characters leaked); see [LIMITATIONS.md](LIMITATIONS.md). The
labelled sets are no longer in the repo, so these can't be re-run. Loading the
lists adds ~1 s per run: a 6 KB transcript takes ~1.4 s, 229 KB ~3.8 s.
