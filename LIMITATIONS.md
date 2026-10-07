# Limitations

Known drawbacks of the PII redaction pipeline (`src/pii/`), as of 2026-09-30.

## 1. Accuracy

Measured on 10 hand-labelled files in `test_data/` (2026-09-30), with
the shipped pre-defined list (only `"Acme Corp"`):

|                                           | Found             | Characters leaked | Over-masked characters | Precision                 |
| ----------------------------------------- | ----------------- | ----------------- | ---------------------- | ------------------------- |
| Names and companies, all files            | 98.5% (390 / 396) | 0.9% (27 / 2912)  | 65                     | 98.2% (7 false positives) |
| Names, normally cased files               | 98.9% (349 / 353) | —                 | —                      | —                         |
| Names, lowercase speech-to-text (4 files) | 95.1% (39 / 41)   | 2.8% (8 / 282)    | 3                      | 100% (no false positives) |

"Found" counts a value as found if it is masked completely. "Over-masked"
counts characters masked that belong to no label. Spelled-out names ("k o f
i", "P-I-C-A-R-D") are labelled but counted apart ("hard"): none of the 6 is
masked.

- **The labelled set is small:** 10 synthetic transcripts, 4 of them
  lowercase speech-to-text. The threshold and filters were tuned on the
  core development files; `asr_bank`, `asr_telecom`, `asr_clinic` and `sme_trans_1` were
  held out and not used for tuning. Real transcripts may do worse. There is no test or
  evaluation tooling in the repository any more, so a change to the rules
  or lists is not measured automatically.
- **Names the model doesn't know are missed**, unless they are listed: "I am
  Shankar.", "Angela Osei", "Gerald Locke" (the model labels them as not a
  name at any threshold). The removed name registries used to catch these.
  **The pre-defined list is the fix**: listing a person's full name also
  covers each part of it ("Shankar Iyer" masks "Shankar" alone).
- **Lowercase speech-to-text is still the weak spot.** Names that are also
  common words are missed when the model misses them: "will" and "will
  mensah" in `asr_sample.txt`. Listing "Will Mensah" catches "will mensah"
  but, by design, not "my brother will" on its own (see section 3).
- **Names that are ordinary words can be missed in normal text too:** "May"
  in _call May tomorrow_.
- **Technical words read as names.** The model tags some product, component
  and place-like names as people: "Service" ×3 ("Cart Service"), "Cascadia"
  ×3 (a company), "Sarahville". Add them to
  `config/undesired-predefined-list.json` as they are found. All-caps
  acronyms ("FHIR", "JSON") are dropped by a filter, unless the whole line is
  in capitals.
- **Every-occurrence rule over-masks capitalised names.** Once a name is
  found, it and each of its parts are masked everywhere: after "Grace
  Hopper", every "Grace"; after a false positive, that word everywhere.
  Lowercase common words are the exception: a found "hope", "bill" or
  "grace" is not spread to its other lowercase uses, so "i hope" and "grace
  period" stay visible. The other side of that: a lowercase name the model
  finds only once stays visible where it misses it.
- **"Common word" is the model's vocabulary**, a 30k-token list that
  contains many first names ("sarah", "tom", "marcus"). In lowercase text,
  such a name is spread only if found whole, and a listed name's lowercase
  part is not matched alone. Capitalised text is not affected.
- **Title, role and relation words are dropped from a model name** ("Mr",
  "Agent", "customer", "wife"), and so are words before one inside a span:
  "thank you mister el sayed" is masked as "el sayed". A name that really
  contains one of these words ("Joy Agent") would leave it visible.
  Greetings and fillers at either end ("hi grace", "priya bye", "yep kofi")
  are trimmed too.
- **Names inside other names are masked as names:** "Whitfield" in
  "Whitfield & Co.", "Ada Lovelace Room". Names inside email addresses are
  masked when found elsewhere (`<PERSON_1>.asante79@gmail.com`); the rest of
  the address stays visible.
- **Only listed companies are masked.** Any company not in
  `config/desired-predefined-list.json` passes through unmasked; keep the list
  current with your clients and partners.

## 2. Scope

Only PERSON and ORGANIZATION are masked. Everything else passes through
**unmasked**, including email addresses, phone numbers, card numbers, IBANs,
dates, SSNs, passport and driver's licence numbers, street addresses,
locations, URLs, IP addresses, and account and reference numbers.

## 3. Rule trade-offs

| Rule                                                | Known wrong result                                                                                                      |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Parts of a listed name match alone                  | A part that is an ordinary word is masked in normal text when capitalised: listing "Will Mensah" masks "Will you call?" |
| Lowercase parts only if not a common word           | "will" of "Will Mensah" is not masked alone in speech-to-text, even when it is the name                                 |
| Short company name only capitalised or in capitals  | "acme" in lowercase speech-to-text is missed; list it explicitly if needed                                              |
| Undesired entries are never masked from the model   | A corrective that is also someone's name ("May", "Will") unmasks that person too, unless the pre-defined list has them  |
| Undesired words trimmed from the edges of a finding | `["Lua"]` turns "Redis Lua" into "Redis", still masked; list each wrong word or the whole phrase                        |
| Model names scored below 0.5 dropped                | Weak but correct names are lost (0.3, 0.4 and 0.5 found the same names; lower only added false positives)               |
| Placeholder numbers                                 | Matching numbers reveal that the same value appeared twice                                                              |

## 4. Languages

English only. The model is English and uncased; Arabic names written in
English are found by the model, but Arabic script is not ("سارة" is
missed). Text in other languages gets little or no name detection; the
pre-defined list still matches.

## 5. Operations

- **The model must be fetched once** (`npm run fetch:model`, 29 MB, needs
  internet). If it is missing or doesn't load, the CLI exits with code 2 and
  writes nothing; so does a missing or malformed list file. The common-word
  list is read from the same model folder.
- **Latency and memory**: see the table in [README.md](README.md); measure on the
  production machine. Almost all of the time is the model's
  own compute, and its threads compete with other load on the CPU, so large
  files vary most. `npm run dev` adds about 1.7 s of `npm`/`tsx` start-up.
- **CPU threads:** the model always uses half the logical CPUs (not
  configurable); running several instances at once on one machine will slow
  each down.
- **Whole document in memory**, 2,000,000-character limit, no streaming.
- **Redaction is one-way.** Originals are not stored or encrypted.
- **CLI only.** A service would still need an HTTP API, PII-free logging and
  metrics.
