# Limitations

Written first, and kept current, because the numbers elsewhere in this
repository are only worth believing if what they do *not* cover is stated
plainly.

## The evaluation set

- **Labels were produced by an AI assistant, not a human annotator, and have not
  been human-verified.** This is the single largest caveat on every accuracy
  figure here. Before these numbers are used to choose a production
  configuration they should be reviewed by someone familiar with the source
  meetings, particularly the spans marked `ambiguous` — a speaker of the
  transcripts' language mix would resolve several cases this labeller could not.
- **No inter-annotator agreement was measured, so none is reported.** A κ
  computed from one labeller would be fabricated.
- **22 excerpts, 168 scored spans.** Enough to separate detector configurations
  from one another, not enough for a per-type F1 on most types: eight of the ten
  types have fewer than ten supporting spans and are reported as raw counts.
- **PERSON is 86% of the set**, because speaker-label lines are the majority
  class in any transcript. The `No-speaker F1` column exists for that reason and
  is the more honest headline.
- **Excerpts, not whole documents.** Labelling a 14 KB transcript exhaustively
  is a multi-hour task with real attention decay, and a partially labelled
  document makes precision uncomputable — every unlabelled true entity becomes a
  phantom false positive. Excerpts are exhaustively labelled instead.
- **Two transcripts from one organisation.** Both are Egyptian-Arabic-accented
  ASR or minutes from the same project. Results will not transfer to other
  domains, languages or recording setups without re-measurement.

## What the sweep measures

- **Detection, not protection.** The sweep stops after entity aggregation; the
  policy engine does not run. Several reported false positives are entities the
  policy layer would *allow* rather than protect — `Cortana` is the clearest
  case. Precision against what actually reaches the mapping is higher than the
  precision column shows.
- **The participant registry is weaker in evaluation than in production**,
  because it is built per excerpt. A name that speaks elsewhere in the meeting
  but appears only in this excerpt's body is not a known participant, so
  registry recall is understated in every configuration that includes it.

## The Qwen layer

- **Implemented and unit-tested against recorded fixtures, never executed
  against a real model.** Configurations C, F and G are reported as `skipped`
  with a reason, never as zero. Nothing in this repository claims a measured
  Qwen result.
- Enabling it requires `ollama pull qwen2.5:7b-instruct` and
  `GATEWAY_QWEN_ENABLED=true`. Its detection quality on these transcripts is
  unknown.

## Performance

- **One machine, CPU only**, 16 logical cores, no CUDA. Figures will differ
  substantially elsewhere, and the provenance block in each results file records
  the machine so they can be compared.
- **`p99` is never reported below n=100 and `p95` below n=20.** A p99 from 30
  samples is the maximum wearing a percentile's name. The suppression happens in
  the data, not in prose.
- **End-to-end mode is confounded and says so.** The baseline and protected arms
  send different prompts and receive different-length completions; completion
  length dominates model latency. The difference in model time between arms is
  not attributable to the gateway. Only `protected_overhead_seconds` is.
- **Peak memory is high and its profile is unstable.** The model-backed
  configuration has a 2.6 GB footprint after warmup. An earlier n=10 run
  appeared to show ~1.2 GB of growth across iterations; the n=30 run shows RSS
  *falling* by a similar amount instead, so that reading was a garbage-collection
  artifact rather than a leak. Neither figure is a reliable steady-state number,
  and peak RSS should be measured under the intended concurrency before sizing
  anything.
- **Model-backed latency is highly variable**: p95 of 15.8 s against a 8.95 s
  median on identical input, stdev 3.6 s. That spread would need to be
  understood before committing to a latency target.

## Detection gaps found by running real documents through the gateway

Running `privacy-gateway run` over a broader corpus of realistic documents
(interview transcripts, support tickets, config files, financial forms)
surfaced detection gaps that the original two-transcript acceptance suite
could not, since it never exercised these shapes of input. Each below is
either fixed with a test pinning the fix, or is a known, documented residual
gap.

- **A bare 3-digit CVV and a bare `MM/YY` expiry are not detected.** Both are
  contextually sensitive next to a card number, but a general regex for "any
  3-digit number" or "any digit/digit token" would false-positive constantly
  against ordinary quantities, ports and dates elsewhere in a document. Left
  undetected deliberately; a semantic detector (Qwen) is the right tool for
  this contextual case, not a pattern.
- **A SWIFT/BIC code with an all-letter branch suffix (the common default
  `XXX`) is not detected.** The pattern requires at least one digit somewhere
  in the token specifically so it cannot be confused with an ordinary
  all-caps English word or acronym of the same length; that same requirement
  costs recall on the letters-only case. Pinned by test as a stated
  trade-off, not a silent gap.
- **A connection-string authority (`user:password@host:port`) is protected as
  one coarse block** rather than splitting user, password and host apart.
  A password containing its own literal `@` -- which this project's own test
  corpus turned out to use -- makes a precise split ambiguous without
  URL-decoding, and the previous behaviour (an email-address pattern
  partially matching into the middle of the string) left part of the
  password in plain text next to the placeholder. Redacting the whole
  authority, host included, is coarser but cannot leak a fragment.
- **A bare, unlabelled run of 6-17 digits is never treated as an account or
  routing number.** Detection is anchored to an explicit label ("Routing
  number:", "Account number:") immediately before the digits; on its own the
  same digit run is too common a shape (a reference number, a zip+4, a
  quantity) to detect safely. A label-free account number in unstructured
  prose will not be caught by this layer.

## The gateway itself

- **Restoration is exact except for case-folded variants.** Two spellings of one
  entity share a placeholder, and restoration emits the first-seen spelling, so
  `ahmed farid` comes back as `Ahmed Farid`. Pseudonymization itself is lossless
  — proven by exact inversion on both transcripts — and every divergent spelling
  is recorded and reported as `case_variants`.
- **Ambiguous names are protected but never attributed.** `pod_meeting.txt` has
  three Ahmeds, so a bare "Ahmed" gets its own placeholder rather than being
  resolved to one of them. The model therefore sees them as different people and
  may under-merge coreference in a summary. This is deliberate: guessing would
  make the gateway fabricate attributed statements in a meeting record.
- **Detector coverage is a privacy decision, not a performance one.** The
  deterministic-only configuration (`regex,registry,domain`) leaves
  `Robert Taylor` and `James Anderson` in `sme_meeting_transcript.txt`: neither
  speaks in the meeting, so the participant registry never sees them, and
  neither is in the lexicon. The full set finds both. The 120x speed-up is real
  and so is the recall it costs. Pinned by test.
- **The pre-send leak gate is not a detector.** It catches a value that was
  detected and then failed to be replaced. It cannot catch a value that was
  never detected, because such a value is not in the mapping to be scanned for.
- **Over-redaction on noisy ASR is expected.** `pod_meeting.txt` is a stream of
  first names and transliterations; with every layer enabled, much of it becomes
  placeholders and summary quality drops. That is correct privacy behaviour but
  it is a real utility cost.
- **Streaming is off by default** and degrades three protections when enabled:
  the drift-retry loop cannot run once tokens are emitted, fail-closed response
  blocking is unavailable, and whole-response patterns can straddle the
  hold-back boundary. Enabling it stamps `degraded_protections` into the report.
- **No adversarial red-teaming beyond the scripted cases** in `tests/security/`.
- **The common-word filter is curated, not derived.** 437 words chosen for this
  domain. A deployment in another domain will need to extend it, and a company
  genuinely named after a common word must be added to the domain lexicon to be
  protected.

## Repository history

- **Earlier commits contain unredacted meeting content.** The generated reports
  and sanitized artifacts were untracked and gitignored, and the prototype's
  corrupted output was moved under `tests/regression/fixtures/` as pinned
  evidence, but `git log` still holds the original blobs. Removing them would
  require rewriting history, which was deliberately not done. If this repository
  becomes public, that decision should be revisited.
