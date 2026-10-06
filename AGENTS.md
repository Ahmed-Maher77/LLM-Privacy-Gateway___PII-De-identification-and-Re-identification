# AGENTS.md

## Project Overview

This is an evaluation Proof of Concept (POC) evaluating **WinkNLP** combined with deterministic rules for PII (Personally Identifiable Information) detection, normalization, and sanitization.

The system evaluates:
- Native entity capabilities and limits of `wink-eng-lite-web-model`
- Deterministic regex rules for structured identifiers (EMAIL, PHONE, URL, IP, SSN, CREDIT_CARD, ADDRESS)
- Character offset reconstruction and strict offset verification
- Non-overlapping span normalization and structural guards
- Decoupled reversible pseudonymization (numbered masking and de-anonymization)
- Quantitative precision, recall, F1-scores, and performance benchmarks

## General Development Rules

- Write production-quality, type-safe TypeScript code (ESM).
- Prefer simple, maintainable solutions over unnecessary abstractions.
- Do not introduce external dependencies or network APIs (all processing must remain 100% local and deterministic).
- Keep detection, normalization, and masking strictly decoupled.
- Follow the existing project architecture and conventions.
- Do not modify unrelated files.

## Documentation First — read `docs/` before reading `src/`

`docs/` exists so you do not have to read every source file to understand behaviour.
**Read the relevant doc before exploring the codebase or diagnosing output.**

| Read | When |
| --- | --- |
| [docs/README.md](docs/README.md) | Always. One-page state of the system and where to go next. |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Pipeline, module map ("which file do I change for X"), and the invariants you must not break. |
| [docs/WINKNLP-CAPABILITIES.md](docs/WINKNLP-CAPABILITIES.md) | **Before assuming WinkNLP detects any entity type.** The model has no PERSON/ORG/LOCATION NER. Check the matrix first. |
| [docs/KNOWN-ISSUES.md](docs/KNOWN-ISSUES.md) | **Before reporting or re-diagnosing any wrong output.** Every known defect is registered with evidence, root cause, and a fix plan. |
| [docs/IMPROVEMENT-PLAN.md](docs/IMPROVEMENT-PLAN.md) | **Before implementing any fix to a registered defect.** Executable task plan (T0-T9) with pre-verified regexes, the exact target output, and a do-not-do list. |

Rules:

- If output looks wrong, **check `docs/KNOWN-ISSUES.md` first**. If it is already
  registered (KI-00x), reference the ID rather than re-investigating from scratch.
- If you find a new defect, **add it to the register** with an ID, evidence from a real
  run, root cause, and whether the cause is our code or a package limitation. Do not
  leave findings only in chat.
- When you fix a registered issue, **update or remove its entry** in the same change.
  Do not let the register drift out of date.
- When you change the pipeline, a module boundary, or a detection strategy,
  **update `docs/ARCHITECTURE.md`** in the same change.
- Always distinguish **package limitation** from **implementation defect** and say
  which, with evidence. Do not attribute our bugs to WinkNLP.

## PII Detection Rules

- Detection must stay **local and deterministic**. No network calls, no LLM in the
  detection or masking path.
- **Sanitizers match shape, not validity.** Mask anything *shaped like* sensitive data.
  Checksum and issuance rules (Luhn, SSA area/group rules) set *confidence*; they must
  never be hard gates that discard a match. A fake or mistyped SSN or card number is
  still a disclosure. See KI-002 and KI-003.
- **Never map a POS tag directly to a PII type.** `PROPN` means proper noun, not person.
  Person detection must be anchored (trigger phrases, titles, name shape) or supplied by
  the caller. See KI-001.
- **Do not add a config toggle without a detector that emits its type.** A toggle with no
  emitter is a silent lie about coverage. See KI-004.
- Denylists of forbidden words are not an acceptable precision strategy against an open
  vocabulary.
- Keep the offset invariant: `text.slice(start, end) === value` for every match.
- Any change to detection must be measured on `samples/large_sample.txt` via
  `npm run demo`, and on precision/recall via `npm run evaluate`. Report both
  false positives and false negatives — never only one.

## Testing & Quality Assurance

For every change:
- Run `npm test` to verify all unit and regression tests pass.
- Run `npm run demo` to verify reference masking and audit report output.
- Run `npm run evaluate` to check precision, recall, and F1 across cohorts.
- Check for lint and type correctness (`npm run build`).
- Ensure no absolute host paths, personal tokens, or unmasked confidential data leak into output files.