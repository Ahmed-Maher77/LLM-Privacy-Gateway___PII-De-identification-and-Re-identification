# Labelling guideline, version 1.0

Written **before** labelling began. Deciding the hard calls up front is the only
way to avoid rationalising them case by case, and the hard calls in this corpus
are predictable.

## Unit of work

Label **excerpts, exhaustively** — never whole files.

A partially labelled document is worse than an unlabelled one: every true entity
the labeller did not reach becomes a phantom false positive, so precision is
understated by an unknown amount and is no longer computable. Exhaustiveness
inside a bounded unit is what makes precision mean anything.

An excerpt is a contiguous run of **whole speaker turns**. Turn-aligned because
speaker-label lines carry most of the PERSON entities, and a mid-turn cut would
orphan them.

## Procedure

1. **Sample deterministically.** `scripts/sample_excerpts.py --seed 20260927`.
   The seed is recorded in the dataset so the sample is reproducible and
   demonstrably not chosen for being easy.
2. **Pass A — recall first, candidates hidden.** Read the excerpt cold and write
   down every sensitive span. This pass may not be skipped or reordered. Looking
   at machine candidates first anchors the gold set onto the detectors being
   measured, and measured recall then approaches 100% by construction — it
   becomes "recall against what my detector already found".
3. **Pass B — adjudicate.** Now reveal the machine candidates. Accept, reject or
   adjust each. A span you wrote in Pass A is `human_added`; one you accepted
   from a candidate is `human_accepted_candidate`. Boundary adjustments count as
   `human_added`, because the final span is yours.
4. **Record the hard calls** in `ADJUDICATION.md`.

`test_at_least_fifteen_percent_of_spans_are_human_added` enforces step 2
mechanically. If almost every gold span was proposed by a detector, Pass A was
skipped.

## Rulings

**People**

- Speaker-label lines (`Ahmed Farid   0:31`) *are* PERSON. They are also the
  majority class, so metrics are reported both including and excluding them —
  an F1 dominated by 190 identical header names is theatre.
- A first name alone (`Hossam.`, `Ahmed`) *is* PERSON.
- A name that cannot be attributed is still PERSON. When three participants
  are called Ahmed, a bare "Ahmed" is labelled without deciding which one it is.
- ASR-mangled name-like tokens (`Tarik`, `Nabeel`, `Big Jamboree`) →
  `certainty: ambiguous`. Excluded from both numerator and denominator, counted
  separately. Guessing here would silently set the ceiling for every detector.
- Possessives: the span excludes `'s`.

**Organisations and systems**

- `Exampleco`, `BrightPath Logistics`, `NorthStar Systems`, `Green Valley Foods`
  → ORGANIZATION or CUSTOMER. A client company is CUSTOMER; a vendor or the
  supplier itself is ORGANIZATION.
- `FleetCore`, `CustomerDesk`, `BillingPro`, `OpsHub` → INTERNAL_SYSTEM, a
  separate type. Folding them into ORGANIZATION would inflate ORG recall while
  hiding whether confidential systems are actually protected.
- Public products and vendors — `Microsoft`, `Teams`, `SharePoint`, `Azure`,
  `GitHub`, `Outlook`, `Chrome`, `Cortana` — are **not** labelled. They identify
  nobody. `Cortana` is called out explicitly because the prototype detected it
  as a person and corrupted it into `<PER_11>rtana`.

**Places**

- A public city or country on its own (`London`, `Manchester`, `Dubai`, `Egypt`)
  is **not** labelled. It identifies nobody, and protecting it makes a summary
  unreadable while protecting nothing.
- A *named facility* is labelled LOCATION: `Dubai Internet City` is a specific
  data-centre campus, not a city. The span excludes the trailing common noun,
  so `Dubai Internet City data center` yields `Dubai Internet City`.

**Identifiers**

- `BP-28491` → CUSTOMER_ID.
- Email addresses → EMAIL, excluding any wrapping backticks.
- `+44 7700 900123` → PHONE.
- An internal API URL → INTERNAL_URL. A public documentation URL is not
  labelled.

**Not sensitive**

- Dates and times, including Teams timestamps and markdown speaker headers.
  `DATE` is excluded from scoring on both sides.
- Money and quantities (`$80,000`, `420 employees`, `4.6`).
- Job titles, unless they name a person.

## Span convention

Maximal span, always. `Dubai Internet City` is one LOCATION, not three
entities — the prototype produced `<LOC_3> <ORG_6> <LOC_4>` for it, which is the
failure this rule prevents.

## Certainty

| Value | Meaning |
|---|---|
| `certain` | unambiguous in context |
| `probable` | almost certainly an entity; context is thin |
| `ambiguous` | could not be resolved; **excluded from scoring** |

Headline metrics use `certain` + `probable`.

## Who produced these labels

**An AI assistant, reading each excerpt. Not a human annotator, and not
human-verified.** This is recorded in `labeler` on every record and repeated in
the dataset summary and in `LIMITATIONS.md`, because it is the single most
important caveat on every number derived from this set.

The `provenance` field still does useful work regardless of who labelled:
`accepted_candidate` marks spans that also appear in the shipped domain lexicon
or allowlist — that is, spans the detectors were always going to find, because
they and the label come from the same curated source. `independent` marks spans
identified from the text alone. If the independent share were near zero, recall
against this set would be high by construction and would mean nothing.

**No inter-annotator agreement is reported**, because none was measured.
Inventing a κ would be exactly the kind of fabricated number this project
exists to avoid.

Before these figures are used to choose a production configuration, the set
should be reviewed by a human familiar with the source meetings — particularly
the `ambiguous` spans, where a native speaker of the transcripts' language mix
would resolve several cases this labeller could not.
