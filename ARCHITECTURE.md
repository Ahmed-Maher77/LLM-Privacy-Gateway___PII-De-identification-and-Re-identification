# How the pipeline works

English-only PII redaction for support transcripts. Four independent
detection layers find values; one merge step combines them; every value is
replaced with a numbered placeholder. Nothing is stored: redaction is one-way.

```text
file ─▶ src/index.ts ─▶ redact() ─▶ detect()
                                      ├─ 1. pre-defined list   layers/predefined.ts
                                      │     name/org lists     layers/dictionary.ts  (data/lists/)
                                      ├─ 2. regex              layers/regex.ts
                                      ├─ 3. Presidio           layers/presidio.ts ──▶ analyzer :5002
                                      ├─ 4. wink-nlp           layers/wink.ts
                                      ├─ every occurrence of a found value
                                      └─ merge overlaps
                         ─▶ Placeholders (policy.ts) ─▶ reports/<name>__sanitized.txt
```

## Types

PERSON, ORGANIZATION, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, IBAN_CODE,
DATE_TIME, US_SSN, US_PASSPORT, US_DRIVER_LICENSE (`ENTITY_TYPES` in `types.ts`).
Everything else passes through.

## The layers

Each layer takes the original text and returns spans with offsets into it.
No layer depends on another.

| Layer | Finds | How |
| --- | --- | --- |
| 1. Pre-defined list | whatever you list, and the **only** source of ORGANIZATION | `config/predefined-list.json`, per type: `{ "PERSON": ["Sarah Johnson"], "ORGANIZATION": ["Exampleco Inc"] }`. Case-insensitive, whole words. |
| 1b. Name lists | names (English, and Arabic written in English) | Registry lists in `data/lists/` (next section), each hit checked by a rule so list entries that are also English words ("Will", "Grace") don't match on their own. |
| 2. Regex | emails, cards, IBANs, SSNs, passports, driver's licences, phones, dates | Fixed formats. Cards must pass Luhn, IBANs mod-97. Passports and licences need a keyword first ("passport number is …"). |
| 3. Presidio | names (spaCy `en_core_web_lg`), plus Presidio's own recognizers for the other types | Our types are requested, except ORGANIZATION. Results under score 0.4 are dropped; phone hits shaped like an IPv4 address are dropped. spaCy's names end at the first line break and before the first word with a digit ("Ahmed Hamed 1 minute" → "Ahmed Hamed"). A name made only of English words is dropped unless one is a listed given name ("Audio" goes, "Grace Hopper" stays), and so is a lowercase name on a line with capitals. Long text goes in ~8,000-character chunks split at line breaks, 4 at a time. |
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

- **Full name:** 2–4 capitalised words starting with a given name, each next
  word a given name, a surname or not an English word, with at least one word
  that isn't English: "Mohamed Ahmed Hassan", "Kofi Mensah". Particles are
  allowed ("Abdel Rahman El-Hamed", "van Dijk"), and fused ones are stripped
  for the lookup ("Elsharif", "Al-Rashid"). Not a place ("New York"), not
  starting or ending with a place or organisation word ("Rue de la Paix",
  "Lincoln Street", "Grace Hopper Lab"), not ending in a code ("Houston TX").
- **Single name:** a given name that is neither an English word (wink's
  lexicon), a place, a filler or a common Arabic expression ("Uhh",
  "Salam", "inshallah"), nor a word with an inner capital ("IDs"): "Youssef", "Priya". Lowercase ("kofi") only on an
  all-lowercase line, i.e. speech-to-text.

## After the layers (`redact.ts`)

1. **Every occurrence.** A value found once is masked everywhere in the
   document, and each part of a found name too: after "Sarah Chen", also
   "Sarah" and "Chen" alone (titles like "Mr" excluded). spaCy often misses
   a name the second time it appears.
2. **Merge.** Overlapping spans become one span covering all of them, so
   nothing a layer found stays partly visible. It takes the type of the
   longest piece.
3. **Placeholders** (`policy.ts`). Each span becomes `<TYPE_N>`. The same
   value (ignoring case and separators; digits only for cards, phones and
   SSNs) gets the same N within a document. "Sarah Chen" and "Sarah" are
   different values.

## Design rules

- **Offsets come from the original text.** Presidio counts Unicode
  codepoints, JS counts UTF-16 units, so Presidio offsets are converted. wink
  offsets are rebuilt from its tokens, and the run fails if a token doesn't
  match the text.
- **Fail closed.** If Presidio is unreachable, or input is over 2,000,000
  characters, the run stops with no output.
- **Merging favours masking.** When layers disagree about where a value ends,
  the union is masked.

## Presidio sidecar (`presidio/`)

| File | Role |
| --- | --- |
| `docker-compose.yml` | analyzer image pinned by digest, port 5002, `PRESIDIO_ANALYZER_WORKERS` (default 4) |
| `analyzer.yml` | `en` only; `default_score_threshold: 0` (the layer applies its own 0.4) |
| `nlp.yml` | spaCy `en_core_web_lg`; maps PER/ORG/GPE/LOC/NORP to Presidio types |
| `recognizers.yml` | only the predefined recognizers for our types; the analyzer must be restarted after editing it |

spaCy's ORG results are not requested: companies come only from the
pre-defined list.

## Checking a change

There are no unit tests. `npm run check` redacts every `test_data/*.txt` and
compares the result with `test_data/expected/`. After an intended change,
review the differences, then save them with `npm run check -- --update`.
