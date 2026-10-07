# WinkNLP capability matrix — check before assuming

Model in use: `wink-eng-lite-web-model` (see `node_modules/wink-eng-lite-web-model/README.md`).

## The hard limit

> The model is trained to detect **CARDINAL, DATE, DURATION, EMAIL, EMOJI, EMOTICON,
> HASHTAG, MENTION, MONEY, ORDINAL, PERCENT, TIME, URL**.
> — `wink-eng-lite-web-model` README, "Named Entity Recognition (NER)"

**There is no `PERSON`, `ORG`, `GPE`, `LOC`, or `ADDRESS` class. Not disabled — not trained.**
No configuration, option, or version bump within this model exposes them. This is the one
genuine package limitation in the project; everything else in
[KNOWN-ISSUES.md](./KNOWN-ISSUES.md) is our own code.

## What WinkNLP gives us, and whether it is PII

| wink entity | PII? | Currently mapped in `mapWinkEntityToPIIType()` |
| --- | --- | --- |
| `EMAIL` | yes | yes (regex wins the overlap; +0.05 method score) |
| `URL` | yes | yes |
| `DATE` | sometimes (DOB yes, document date no) | yes, gated by `config.date` (default `false`) |
| `TIME` | rarely | yes, gated by `config.time` (default `false`) |
| `MENTION` | sometimes | yes, gated by `config.mention` (default `false`) |
| `CARDINAL` / `ORDINAL` / `MONEY` / `PERCENT` / `DURATION` | no | intentionally `null` |
| `EMOJI` / `EMOTICON` / `HASHTAG` | no | intentionally `null` |
| — `PERSON` | — | **does not exist** |
| — `ORG` | — | **does not exist** |
| — `LOC` / `GPE` | — | **does not exist** |

Because DATE/TIME/MENTION default to `false` and the numeric classes map to `null`,
**WinkNLP's NER contributes almost nothing under default config** — effectively only
EMAIL and URL, both of which the regex engine already covers more precisely.

## Verified observation on the reference sample

Running wink directly over `samples/large_sample.txt`, the *entire* NER output is:

```text
DATE      2023-10-27 | today | 04/12/1985
EMAIL     mike.rodriguez88@example.com | m.rodriguez@example.org
CARDINAL  742 | 97403 | 555 | four | 4321 | 4111 | 2222 | 3333 | 4321
DURATION  day
```

No names. No organizations. No locations. Any `[PERSON]` tags in the output come from the anchored person rules
(`person-detector.ts`), not from this list.

## What the POS tagger *is* good for

POS tagging is ~95% accurate and genuinely useful — but `PROPN` means
*"proper noun"*, **not** *"person"*. On the reference sample the tagger correctly
labels all of these `PROPN`:

```text
Test  Case  ID  Date  Customer  Support  Log  TRANSCRIPT  Agent  System
SecureBank  Sarah  Jenkins  User  Michael  Rodriguez  Mike  Mr.
Evergreen  Terrace  Springfield  Perfect  Visa  END
```

The tagger is right. Mapping that set to `PERSON` is our error. Six of those tokens
denote people; the rest are document labels, speaker roles, a bank, a card brand, a
street, a city, and an adjective at sentence start.

`Perfect` and `Visa` are instructive: both are sentence-initial or brand-cased, so
`PROPN` is a defensible tag — and both are meaningless as PII.

## Practical guidance

- **Do** use wink for tokenization, sentence splitting, offsets, and POS structure.
- **Do** use POS as a *supporting signal* inside an anchored rule
  (e.g. "the `PROPN` run immediately following `my name is`").
- **Do not** use `PROPN` alone as a PII classifier. Capitalisation is not identity.
- **Do not** try to fix it with a denylist. A fixed blocklist against an open vocabulary
  always loses; the removed `NON_PERSON_WORDS` list failed on `Agent`, `Perfect`,
  `Visa`, `Log`, `System`, `Date`, `END`, `TRANSCRIPT`.

## If real name/org/location NER is required

WinkNLP cannot provide it. Options, roughly in order of cost:

1. **Anchored deterministic rules + optional caller-supplied name list.** No new
   dependency, high precision, recall limited to anchored mentions. Best fit for this
   POC's stated constraints (local, deterministic, no LLM for critical logic).
2. **A dedicated NER model** (e.g. an ONNX transformer NER runtime). Real recall, but
   adds a heavy dependency and inference latency — weigh against
   [README.md](../README.md#10-performance-results) performance targets.
3. **A managed PII service.** Breaks the "runs completely locally, no data leaves the
   process" property that is a headline claim of this POC. Not recommended.
