# Limitations

Known drawbacks of the PII redaction pipeline (`src/pii/`), as of 2026-09-30.

## 1. Accuracy

Measured with `npm run eval` on the 8 labelled files in `test_data/`:

| | Found | Characters leaked | Precision |
| --- | --- | --- | --- |
| Names, all files | 99.1% (329 / 332) | 0.5% | 98.2% (6 false positives) |
| Names, normally cased files | 99.7% (318 / 319) | — | — |
| Names, lowercase speech-to-text (`asr_sample.txt`) | — | 10.8% (8 / 74) | — |
| All types | 99.2% (378 / 381) | 0.4% | 98.4% |

"Found" counts a value as found if it is masked completely, as any type.
Spelled-out and spoken forms, Arabic script and checksum-failing numbers are
labelled but counted apart ("hard"): none of the 10 is masked.

- **The labelled set is small:** 8 synthetic transcripts, one of them
  lowercase speech-to-text. The threshold and filters were tuned on it, so
  real transcripts may do worse. Add anonymised real transcripts with labels
  to `test_data/` to measure them.
- **Lowercase speech-to-text is still the weak spot.** Names that are also
  English words are missed when the model misses them: "will" and "will
  mensah" in `asr_sample.txt` (only "will" leaks).
- **Names that are ordinary words can be missed in normal text too:** "May"
  in *call May tomorrow*. The lists deliberately don't match such words alone.
- **Spelled-out names** ("P-I-C-A-R-D", "k o f i") are not detected.
- **Spoken numbers, dates and emails** ("seven three zero six", "march third
  nineteen eighty two", "kofi dot mensah at gmail dot com") are not detected.
- **Technical words read as names.** The model tags some product and language
  names as people ("Lua" ×4 in the test set), and made-up place names
  ("Sarahville"). All-caps acronyms ("FHIR", "JSON") are dropped by a filter,
  unless the whole line is in capitals.
- **Every-occurrence rule over-masks.** Once a name is found, each of its parts
  is masked everywhere: after "Grace Hopper", every "Grace"; after a false
  positive, that word everywhere. "grace" in *grace period* is masked in the
  test set this way.
- **Names inside place or organisation names** ("Ada Lovelace Room", "Martin
  Luther King Jr Way") are masked as names.
- **Leading English words are trimmed from a model name** unless they are
  listed given names: "Agent David" becomes "David". The given-name list is
  wide ("Hill", "Baker", "Brown" are in it), so real names rarely lose a word,
  but a name that starts with an unlisted English word would leave it visible.
- **Only listed companies are masked.** Any company not in
  `config/predefined-list.json` passes through unmasked; keep the list
  current with your clients and partners.
- **The name lists are not complete.** Wikidata lacks many rare surnames.
  Put known people in `config/predefined-list.json`.

The pre-defined list is the reliable fix for names you know in advance.

## 2. Scope

Only the types listed in ARCHITECTURE.md are masked. Everything else passes
through **unmasked**, including street addresses, locations, URLs, IP
addresses, account and reference numbers, and non-US government IDs.
`DATE_TIME` covers calendar dates (in digits, with a month name, or in words
wink-nlp recognises); times of day, durations and weekdays are not masked.

## 3. Rule trade-offs

| Rule | Known wrong result |
| --- | --- |
| Passport / driver's licence after a keyword | An ID given with no keyword before it is missed, unless the passport rule below finds it |
| Passport shape on a "passport" line | Any 9-digit number (or letter + 8 digits) on a line mentioning "passport" is masked as a passport |
| Dashed SSN shape | Any `ddd-dd-dddd` number is masked as an SSN, unless it is in an impossible range (area 000, 666 or 900–999, group 00, serial 0000); a mistyped SSN in such a range stays visible |
| Card needs a valid Luhn checksum | A mistyped card number is missed |
| IBAN needs a valid mod-97 checksum | A mistyped IBAN is missed |
| International phones checked by `libphonenumber-js` | A number that isn't valid for its country code is missed |
| Model names scored below 0.5 dropped | Weak but correct names are lost (0.1–0.6 scored the same on the test set; 0.7 lost a name) |
| Placeholder numbers | Matching numbers reveal that the same value appeared twice |

## 4. Languages

English only. The model is English and uncased; Arabic names written in
English are found by the model and the name lists, but Arabic script is not
("سارة" is missed). Text in other languages gets little or no name
detection; the regex types (email, phone, card, IBAN, dates in digits) still
match.

## 5. Operations

- **The model must be fetched once** (`npm run fetch:model`, 29 MB, needs
  internet). If it is missing or doesn't load, the CLI exits with code 2 and
  writes nothing.
- **Latency and memory** (8-core laptop, median of 5; `npm run bench`
  re-measures on any machine): *cold* is one CLI run including loading the
  lists and the model, *warm* a later call in the same process. Memory is the
  model, the name lists and Node.js.

  | Input | Cold | Warm | Peak memory |
  | --- | --- | --- | --- |
  | 6 KB | 1.4 s | 0.19 s | 0.45 GB |
  | 60 KB | 2.8 s | 1.6 s | 0.46 GB |
  | 229 KB | 8.6 s | 7.0 s | 0.49 GB |

  Measured with other apps using ~30% of the CPU; the model's threads compete
  with them, so large files vary most (229 KB warm ranged 6.1–11.8 s, and
  took 5.2 s in quieter tuning runs). `npm run dev` adds about 1.7 s of
  `npm`/`tsx` start-up. Almost all of the large-file time is the model's own
  compute; revisit if production transcripts are much larger than 60 KB.
- **CPU threads:** the model uses half the logical CPUs (`NER_THREADS`);
  running several instances at once on one machine will slow each down.
- **The lists are a snapshot** of Wikidata and GeoNames on the build date;
  rerun `npm run build:lists` to refresh.
- **Whole document in memory**, 2,000,000-character limit, no streaming.
- **Redaction is one-way.** Originals are not stored or encrypted.
- **`reports/` is not git-ignored.**
- **CLI only.** A service would still need an HTTP API, PII-free logging and
  metrics.

## 6. Measurement

- `npm run eval` scores against labels that one person reviewed; the labels
  decide every tuning choice, so review label changes carefully.
- The previous pipeline's reference (`test_data/reference/`) is its saved
  output, which predates some rule changes: its 16 company false positives
  would not happen today. Treat it as a rough reference.
- Precision counts a masked span as correct if it overlaps a labelled value,
  so extra words masked *with* a name don't lower it. They are counted
  separately as over-masked characters (the "over" column; 41 in total, 202
  for the old pipeline): in `asr_sample.txt` "frank mister mensah" and
  "priya bye" are masked as one name each, hiding "frank" and "bye".
  `--details` lists such spans.
- `npm run check` only detects that output *changed*; whether a change is
  right has to be judged by reading the diff and by `npm run eval`.
