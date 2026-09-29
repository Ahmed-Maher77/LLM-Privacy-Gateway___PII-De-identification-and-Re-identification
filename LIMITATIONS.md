# Limitations

Known drawbacks of the PII redaction pipeline (`src/pii/`), as of 2026-09-29.

## 1. Accuracy

Measured on synthetic labelled sets that are no longer in the repo, so these
can't be re-run:

| Set | Names found | Name precision | Name characters leaked | All types found |
| --- | --- | --- | --- | --- |
| Held-out, normally cased (8 docs) | 96.4% | 88.6% | 1.9% | 96.7% |
| Tuning, normally cased (10 docs) | 87.6% | 81.7% | 7.7% | 91.1% |
| Speech-to-text, lowercase (8 docs) | 62.6% | 90.9% | 36.8% | 65.9% |

"Names found" counts a name as found if it is masked as any type. These were
measured while companies were still detected automatically, which also
masked a few names spaCy labels as organisations; they may now be slightly
lower.

- **Lowercase speech-to-text is the weak spot: about 37% of name characters
  leak.** spaCy depends on capital letters, and the name lists only catch
  lowercase names that aren't English words ("kofi", not "grace" or "hope").
- **Names that are ordinary English words** ("Will", "Grace Hopper", "Mark
  Hill") are left to spaCy; the lists deliberately don't match them alone.
- **Spelled-out names** ("P-I-C-A-R-D", "k o f i") are not detected.
- **Only listed companies are masked.** Any company not in
  `config/predefined-list.json` passes through unmasked; keep the list
  current with your clients and partners.
- **The name lists are not complete.** Wikidata lacks many rare surnames.
  Put known people in `config/predefined-list.json`.
- **Every-occurrence rule over-masks.** Once a name is found, each of its parts
  is masked everywhere: after "Grace Hopper", every "Grace"; after a
  false positive such as a header read as a name, that header word
  everywhere.
- **Names inside place or organisation names** ("Ada Lovelace Room", "Martin
  Luther King Jr Way") are masked as names.
- **Spoken numbers and dates** ("seven three zero six", "march third nineteen
  eighty two") are not detected.

The pre-defined list is the reliable fix for names you know in advance.

## 2. Scope

Only the types listed in ARCHITECTURE.md are masked. Everything else passes
through **unmasked**, including street addresses, locations, URLs, IP
addresses, account and reference numbers, and non-US government IDs. `DATE_TIME` includes times and durations as Presidio reports
them.

## 3. Rule trade-offs

| Rule | Known wrong result |
| --- | --- |
| Passport / driver's licence need a keyword | An ID given with no keyword before it is missed |
| Dashed SSN shape | Any `ddd-dd-dddd` number is masked as an SSN |
| Card needs a valid Luhn checksum | A mistyped card number is missed (unless Presidio finds it) |
| Presidio score below 0.4 dropped | Weak but correct matches are lost |
| Placeholder numbers | Matching numbers reveal that the same value appeared twice |

## 4. Languages

English only. Text in other languages gets no name detection; the regex
types (email, phone, card, IBAN, dates in digits) still match. Arabic would
need a transformers-based NER engine in Presidio.

## 5. Operations

- **Presidio has to be running** (`npm run presidio:up`), about 0.8 GB per
  analyzer worker. If it's unreachable the CLI exits with code 2 and writes
  nothing.
- **Latency:** loading the lists takes ~1 s per run (about 100 MB of memory);
  about 1.4 s for 6 KB, 3.8 s for 229 KB.
- **The lists are a snapshot** of Wikidata and GeoNames on the build date;
  rerun `npm run build:lists` to refresh.
- **Whole document in memory**, 2,000,000-character limit, no streaming.
- **Redaction is one-way.** Originals are not stored or encrypted.
- **`reports/` is not git-ignored.**
- **CLI only.** A service would still need an HTTP API, PII-free logging and
  metrics.

## 6. Measurement

No unit tests and no evaluation harness. `npm run check` only detects that
output *changed* on the 3 files in `test_data/`; whether a change is right has
to be judged by reading the diff.
