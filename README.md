# LLM Privacy Gateway

A Python gateway that detects sensitive data in text bound for a language model,
replaces it with reversible placeholders, and restores the original values in
the model's answer. Input is normalized, scanned by up to six detection layers
(regex, participant registry, domain lexicon, Presidio, BERT NER and an optional
Qwen model), reconciled into one non-overlapping entity list, filtered through a
policy layer and rewritten by offset. **Only the placeholder text reaches the
model.** The mapping stays in the trusted process, and restoration is exact-match
only, with drift detection for placeholders the model has mangled.

Part of the [PII de-identification implementations](../README.md) collection.

> Read [`LIMITATIONS.md`](LIMITATIONS.md) before quoting any number from this
> project. The evaluation labels were produced by an AI assistant, not a human
> annotator, and the Qwen layer has never been run against a real model.

## At a glance

| | |
|---|---|
| **Language / runtime** | Python 3.12+, managed with [uv](https://docs.astral.sh/uv/); CLI `privacy-gateway` and importable package `privacy_gateway` |
| **Approach** | Layered detection (regex, participant registry, domain lexicon, Presidio/spaCy, BERT NER, optional Qwen via Ollama) → aggregation with asserted invariants → policy → offset-based pseudonymization → pre-send leak gate → LLM → output/drift scan → exact restoration |
| **Entities** | Protected by default: PERSON (incl. EMPLOYEE, STAKEHOLDER), EMAIL, PHONE, DATE, SSN, CREDIT_CARD, CUSTOMER, PROJECT, INTERNAL_SYSTEM, INTERNAL_SERVICE, CONTRACT, CONFIDENTIAL_BUSINESS_INFORMATION (incl. credentials). Allowed by default: ORGANIZATION, LOCATION, ADDRESS, URL, INTERNAL_URL, IP_ADDRESS, CUSTOMER_ID, ACCOUNT_IDENTIFIER, PASSPORT |
| **Reversible** | Yes. `pseudonymize` placeholders (`<PERSON_001>`) are restored from a per-conversation, in-memory mapping; `redact` and `mask` actions are available but irreversible |
| **Network at runtime** | `sanitize` needs none (after the BERT model is cached). `run` calls an Ollama daemon; the default downstream model `gpt-oss:120b-cloud` is Ollama-hosted. The optional Qwen layer needs a local Ollama model |
| **Models** | spaCy `en_core_web_lg` 3.8.0 (~425 MB installed), `dslim/bert-base-NER` (~415 MB, Hugging Face cache), optional `qwen2.5:7b-instruct` via Ollama. `.venv` is ~1.4 GB |
| **Best for** | Batch sanitization of English meeting transcripts and business documents before they are sent to an LLM, where business-confidential terms can be listed in a lexicon and seconds of CPU latency are acceptable |
| **Status** | v0.2.0. 643 tests; evaluation harness and benchmark included. Mapping persistence, authentication and streaming are out of scope |

## Contents

- [Quick start](#quick-start)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Why this design](#why-this-design)
- [Policy](#policy)
- [Pseudonymization and re-identification](#pseudonymization-and-re-identification)
- [Security model](#security-model)
- [Evaluation](#evaluation)
- [Performance](#performance)
- [Large inputs and streaming](#large-inputs-and-streaming)
- [Project layout](#project-layout)
- [Production-readiness checklist](#production-readiness-checklist)
- [Testing](#testing)
- [Limitations](#limitations)
- [License](#license)

## Quick start

### Prerequisites

- Python 3.12 or later
- [uv](https://docs.astral.sh/uv/)
- About 2 GB of free disk for the virtual environment and the BERT model
- Optional: [Ollama](https://ollama.com/), only for `privacy-gateway run` with a
  real model, for the Qwen layer, and for `bench.py --mode e2e`

### Installation

From the root of the collection:

```bash
cd 05-python-presidio-bert-qwen-gateway
uv sync --group dev --group models   # `models` installs spaCy en_core_web_lg
cp .env.example .env                 # optional; every default is safe
```

`dslim/bert-base-NER` downloads from the Hugging Face Hub on first use. After
that, set `HF_HUB_OFFLINE=1` if detection must not touch the network.

Without the `models` group the default configuration fails closed (exit code 3)
because the Presidio detector cannot load. The deterministic layers
(`--detectors regex,registry,domain`) work without any model.

### First run

```bash
# Detect and pseudonymize with the deterministic layers only. No models, no network.
uv run privacy-gateway sanitize test_data/sme_meeting_transcript.txt --detectors regex,registry,domain

# Detect and pseudonymize with the default detector set (needs the models above).
uv run privacy-gateway sanitize test_data/sme_meeting_transcript.txt --report reports/sme-sanitize.json

# Full pipeline without Ollama: the `echo` provider returns the prompt verbatim,
# which exercises sanitize -> "model" -> restore end to end.
GATEWAY_LLM_PROVIDER=echo uv run privacy-gateway run test_data/scenario_01_plain_meeting.txt --print-answer

# Full pipeline with the real downstream model (needs Ollama).
uv run privacy-gateway run test_data/sme_meeting_transcript.txt --report reports/sme.json --print-answer
```

The sanitized text is written to `artifacts/<name>__sanitized.txt`
(`GATEWAY_ARTIFACTS_DIR`). Without `--report`, the JSON report is printed to
stdout. `reports/` and `artifacts/` are git-ignored because they can contain
sensitive content.

## Usage

### CLI reference

`privacy-gateway sanitize INPUT_FILE [options]` runs everything except the model
call, which is the useful mode for inspecting what the gateway would send.
`privacy-gateway run INPUT_FILE [options]` adds the model call and restoration.

| Option | Applies to | Description |
|---|---|---|
| `--detectors a,b,c` | both | Comma-separated detector names: `regex`, `registry`, `domain`, `presidio`, `ner`, `qwen` |
| `--fail-mode {closed,open}` | both | Overrides `GATEWAY_FAIL_MODE` |
| `--conversation-id ID` | both | Mapping scope; a random 128-bit id is generated if omitted |
| `--report PATH` | both | Write the JSON report to a file instead of stdout |
| `--include-content` | both | Embed the sanitized input and the answer in the report (the answer contains restored values) |
| `--include-mapping` | both | Embed the placeholder mapping in the report. This is the secret |
| `--instruction TEXT` | `run` | Task instruction sent with the sanitized document |
| `--print-answer` | `run` | Print the restored answer |

Reports omit the sanitized text and the answer unless `--include-content` is
passed, and the mapping unless `--include-mapping` is passed as well. The
prototype embedded real names in every report it wrote.

**Exit codes:** 0 ok · 1 configuration · 2 input too large · 3 detector
unavailable · 4 aggregation invariant or placeholder collision · 5 sanitization
leak, placeholder injection or conversation mismatch · 6 output leak blocked ·
7 model error.

> **The fast configuration is not a safe default for arbitrary documents.**
> `regex,registry,domain` finds structured identifiers, transcript participants
> and configured business terms, and nothing else. Running it over
> `sme_meeting_transcript.txt` leaves `Robert Taylor` and `James Anderson` in the
> text it sends, because neither person speaks in the meeting and neither is in
> the lexicon. The full set finds both. Use the fast configuration when the
> sensitive vocabulary is known in advance and enumerable; otherwise pay the
> latency. This is pinned by test in `tests/regression/`.
>
> The pre-send leak gate catches *detection succeeded but replacement failed*.
> It cannot catch *detection never happened*, because a value nobody detected is
> not in the mapping to scan for. No gate substitutes for detection coverage.

### Library

```python
from privacy_gateway.config import Settings
from privacy_gateway.gateway import PrivacyGateway, GatewayRequest

gateway = PrivacyGateway(Settings.from_env())   # pass llm=... to override the client
result = gateway.run(GatewayRequest(text=transcript, conversation_id="c-123"))

result.output            # answer, with values restored
result.sanitized_input   # what the model actually saw
result.store             # the mapping; never serialized by default
result.warnings          # drift, hallucinated placeholders, degraded detectors
```

To call the model yourself, split the two halves:

```python
outcome = gateway.sanitize(GatewayRequest(text=transcript, conversation_id="c-123"))
answer = my_llm(outcome.sanitized_text)
restored = gateway.restore(answer, outcome.store, conversation_id="c-123")
restored.text, restored.status, restored.drift, restored.unknown, restored.leaks
```

`privacy_gateway.llm.mock_client` provides `EchoLLMClient` and `MockLLMClient`
for offline use and tests.

### Configuration

Every setting is an environment variable with a safe default; `.env` is loaded
automatically. See [`.env.example`](.env.example) for the full annotated list.

| Variable | Default | Effect |
|---|---|---|
| `GATEWAY_FAIL_MODE` | `closed` | `closed` aborts rather than run under weaker protection than configured; `open` continues with a degraded status and a warning |
| `GATEWAY_DETECTORS_ENABLED` | `regex,registry,domain,presidio,ner` | An empty list is refused at startup |
| `GATEWAY_DETECTORS_REQUIRED` | `regex,registry` | Always fatal on failure; under fail-closed every enabled detector is |
| `GATEWAY_PRESIDIO_SPACY_MODEL` / `GATEWAY_PRESIDIO_THRESHOLD` | `en_core_web_lg` / `0.35` | Presidio NLP model and score floor |
| `GATEWAY_NER_MODEL` / `GATEWAY_NER_DEVICE` / `GATEWAY_NER_THRESHOLD` | `dslim/bert-base-NER` / `cpu` / `0.60` | BERT NER settings |
| `GATEWAY_DOMAIN_LEXICON` | `config/domain_lexicon.toml` | Business terms and id patterns |
| `GATEWAY_QWEN_ENABLED` / `GATEWAY_QWEN_REQUIRED` | `false` / `false` | Enabling needs `ollama pull qwen2.5:7b-instruct`; a Qwen failure is fatal only when required |
| `GATEWAY_QWEN_MODEL`, `_BASE_URL`, `_TIMEOUT`, `_MAX_CHARS`, `_MAX_RETRIES` | `qwen2.5:7b-instruct`, Ollama default, `60`, `4000`, `1` | Qwen client settings |
| `GATEWAY_LLM_PROVIDER` | `ollama` | Also `echo` and `mock` (test doubles, no network) |
| `GATEWAY_OLLAMA_MODEL` / `GATEWAY_OLLAMA_BASE_URL` | `gpt-oss:120b-cloud` / Ollama default | Downstream model |
| `GATEWAY_LLM_TEMPERATURE` / `GATEWAY_LLM_TIMEOUT` | `0.0` / `120` | Downstream call settings |
| `GATEWAY_PLACEHOLDER_STYLE` | `angle` | `angle` = `<PERSON_001>`; `guillemet` = `⟦PERSON_001⟧` (no markdown or HTML meaning); `bracket` = `[[PERSON_001]]` |
| `GATEWAY_PLACEHOLDER_PAD` | `3` | Digits in the placeholder index |
| `GATEWAY_REID_UNKNOWN_ACTION` | `redact` | What to do with a well-formed placeholder not in this conversation's mapping (`redact` or `keep`) |
| `GATEWAY_SCAN_OUTPUT` | `true` | Scan the model output for raw sensitive values |
| `GATEWAY_ON_DRIFT` / `GATEWAY_MAX_DRIFT_RETRIES` | `retry` / `1` | One corrective turn when the model mangles placeholders |
| `GATEWAY_BLOCK_ON_INJECTION` | `true` | Abort on placeholder injection (under fail-closed) |
| `GATEWAY_MAX_INPUT_CHARS` | `1000000` | Larger input is refused before any model call |
| `GATEWAY_UNICODE_FORM` | `NFC` | `NFC`, `NFKC` or `none` |
| `GATEWAY_DECODE_HTML_ENTITIES` / `GATEWAY_STRIP_ZERO_WIDTH` | `true` / `true` | Preprocessing |
| `GATEWAY_POLICY_FILE` | `config/policy.toml` | Optional per-type overrides of `policy/actions.py`; not shipped |
| `GATEWAY_ALLOWLIST_FILE` / `GATEWAY_DENYLIST_FILE` | `resources/public_entities.txt` / `resources/denylist.txt` | Policy lists |
| `GATEWAY_ARTIFACTS_DIR` | `artifacts` | Where sanitized text is written |

Data, not code: `config/domain_lexicon.toml` (business terms),
`resources/public_entities.txt` (allowlist), `resources/denylist.txt`,
`resources/common_words.txt`, and the optional `config/policy.toml`.

## How it works

### PII lifecycle

```mermaid
flowchart TD
    classDef gate fill:#fce8e6,stroke:#c5221f,stroke-width:2px,color:#c5221f;
    classDef external fill:#fef7e0,stroke:#ea8600,stroke-width:2px,color:#b06000;
    classDef store fill:#f1f3f4,stroke:#5f6368,stroke-width:2px,stroke-dasharray: 5 5;

    A["1. Raw User Input<br/>Text containing sensitive PII (Names, Emails, Dates, Secrets)"] --> B["2. Multi-Layer Detection<br/>Regex Patterns • Participant Registry • Domain Lexicon • Presidio & NER"]
    B --> C["3. Aggregation & Policy Filtering<br/>Deduplicate & arbitrate overlaps • Enforce public allowlists (ALLOW vs PROTECT)"]
    C --> D["4. De-Identification (Pseudonymization)<br/>Right-to-left offset replacement with reversible tokens (e.g. &lt;PERSON_001&gt;)"]
    
    D -.->|Store mapping locally| S[("Mapping Store<br/>In-memory only • Never sent to LLM")]
    
    D --> E{{"5. Pre-Send Leak Gate<br/>Fail-closed scan ensuring no cleartext PII survives"}}
    E -->|Only sanitized text transmitted| F["6. Downstream LLM<br/>External / local model processes anonymized text"]
    F --> G["7. Re-Identification (Restoration)<br/>Single-pass anchored replacement restoring original entities"]
    S -.->|Restore original values| G
    G --> H["8. Safe Final Output<br/>Coherent completion returned to the caller"]

    class D,E gate;
    class F external;
    class S store;
```

### Pipeline

```mermaid
flowchart TD
    A[Raw input] --> B[Normalize<br/>+ offset map]
    B --> C[Parse transcript<br/>+ participant registry]
    C --> D[Injection guard]
    D --> E{Detection}
    E --> L1[L1 regex + Presidio<br/>deterministic]
    E --> L2[L2 domain lexicon<br/>business knowledge]
    E --> L3[L3 Qwen<br/>semantic · off by default]
    E --> L4[L4 BERT NER<br/>optional signal]
    L1 & L2 & L3 & L4 --> F[Aggregate<br/>validate · trim · align · resolve overlaps]
    F --> G[Policy engine<br/>what to protect]
    G --> H[Pseudonymize<br/>by offset, right to left]
    H --> I{{PRE-SEND LEAK GATE}}
    I --> J[LLM]
    J --> K[Output scan<br/>+ drift scan]
    K --> M[Restore<br/>exact match only]
    M --> N[Answer + safe report]
    H -.->|mapping never crosses| X[( )]
    style I fill:#8b1a1a,color:#fff
    style X fill:none,stroke:none
```

After the policy decision, a consistency sweep finds every remaining occurrence
of each value about to be protected and re-aggregates, so a value detected in
one sentence and missed in the next is still replaced everywhere.

### The five invariants

Everything else serves these.

1. **Entity text is always re-read from the source.** One factory sets
   `text = source[start:end]`. A detector's own idea of what it matched (Hugging
   Face's `word`, Qwen's echoed string) is kept only as a diagnostic flag.
2. **Spans are word-aligned.** A span whose edge falls between two alphanumerics
   is expanded to the whole word (for detectors whose offsets are approximate)
   or dropped.
3. **Replacement is by offset, applied right to left.** There is no
   `str.replace` in the pseudonymizer. An entity at `[start, end)` can only ever
   affect `[start, end)`.
4. **Aggregation post-conditions are asserted and fatal**, in both fail modes:
   output pairwise disjoint and sorted, every span agreeing with the source,
   every span word-aligned.
5. **Restoration is one anchored regex pass.** This eliminates prefix collision
   (`<PERSON_001>` inside `<PERSON_0011>`) and cascading re-substitution
   together.

Invariant 3 alone eliminates the corruption class. The others are independent
backstops.

### Detection layers

| Layer | Priority | What it is for | Fails how |
|---|---|---|---|
| **Registry** | 100 | Speaker labels parsed from the transcript. A *fact about the document*, not a guess | Finding nothing is not an error: a plain document has no speaker lines |
| **Regex** | 90 | Email, phone, SSN, card (any card-shaped number, IBANs excluded), date, credentials and connection strings | Required by default; pure `re` cannot fail without a code defect |
| **Domain** | 80 | Configurable lexicon: internal systems, customers, id formats. Only finds what it is told about | Fatal under fail-closed |
| **Presidio** | 60 | spaCy-backed NER plus validated recognisers | Fatal under fail-closed, with the remediation in the message |
| **NER** | 40 | `dslim/bert-base-NER`. A *signal*, never the authority | Fatal under fail-closed |
| **Qwen** | 30 | Local semantic understanding. **Off by default** | Never fatal unless `GATEWAY_QWEN_REQUIRED=true` |

The ladder ranks *evidence quality*, not model capability. The semantic layer
sits last precisely because it is the most capable: capability is not
reliability, and an LLM's spans are the least trustworthy thing in the pipeline.

Organization, location, URL and IP labels from Presidio and NER are dropped at
detection, because those categories are allowed by policy.

**The NER fix.** On a sentence of names the prototype's configuration
(`aggregation_strategy="simple"`, reading the `word` field) emitted
`##`-prefixed sub-word pieces and one- or two-letter fragments instead of whole
names. The current one (`aggregation_strategy="max"`, offsets re-read from the
source) emits whole names and zero fragments. It also chunks its input
(1,200-character chunks with a 120-character overlap), because the model
truncates at 512 tokens and the back half of a long transcript was previously
invisible to it. That is a correctness bug at any input size, not a scaling
concern.

**The Qwen layer.** The model is **never asked for offsets**. It returns
`{type, text}` only, and each string is re-grounded in the source with an exact,
word-bounded search. A model that invents an entity therefore produces
*nothing* rather than a corrupt span. The parser tolerates fenced JSON, prose
preambles, `<think>` blocks and truncated arrays, counting what it drops.

### Aggregation

Per entity: range check → re-read from source → **trim wrappers** → strip
possessive → newline check → word-boundary align or expand → length floors
(person-like names need at least 3 characters) → ASR-filler and common-word
filters → confidence floor. Every rejection is recorded and reported; silent
drops are how detection regressions hide.

Then: merge exact duplicates (with a capped corroboration bonus) → sort by a
**total order** so no two candidates can tie → linear sweep.

Two rules matter more than they look:

- **An overlap loser is dropped entirely, never trimmed to its remainder.**
  Trimming is how a one-character fragment gets manufactured from the other
  direction: the same defect by a different route.
- **A container is never split around a nested entity.** For the same type the
  container wins (NER's complete `James Anderson` beats Presidio's `Anderson`).
  For different types the higher-priority detection wins, so a high-precision
  regex `EMAIL` inside a sloppy model span is not swallowed.

The wrapper-trim step is also the generic fix for a real bug in the preserved
`EMAIL_PATTERN`: its local-part character class contains a backtick, so every
match in a markdown-code-spanned address started one character early. Trimming
fixes that *and* `**FleetCore**` *and* `Ahmed,` with one rule.

## Why this design

### The problem

A meeting transcript sent to a hosted model carries names, email addresses,
phone numbers, customer identifiers, internal system names and contract
references. Redacting them destroys the document. Replacing them with stable
placeholders preserves the structure the model needs while disclosing nothing.
The intended transformation (illustrative):

```
Create a proposal for Ahmed from Microsoft. Sarah Johnson will manage
the project. Contact Ahmed at ahmed@example.com.
```

becomes

```
Create a proposal for <PERSON_001> from Microsoft. <PERSON_002> will manage
the project. Contact <PERSON_001> at <EMAIL_001>.
```

`Microsoft` is left alone deliberately: it is a public company and identifies
nobody, and pseudonymizing it would cost meaning for no privacy gain. That
decision belongs to the policy layer, not the detectors.

With the shipped default detectors the last sentence currently comes out as
`<PERSON_003> at <EMAIL_001>`: spaCy, via Presidio, reports `Contact Ahmed` as
one person span. Nothing leaks, but the second mention gets its own placeholder.

### Why this was rebuilt

The previous implementation detected entities with one NER model, **discarded
the offsets**, and anonymized with `str.replace()` on the surface strings. The
first three rows were measured on the prototype's run over a real meeting
transcript that has since been removed; the last two are reproducible from
`tests/regression/fixtures/prototype_v0/`:

| Evidence | What it shows |
|---|---|
| 138 corrupted sites, 28 distinct | Sub-word fragments became entities and were replaced document-wide, e.g. `<PER_23>y` ×58 |
| 24 invented words | e.g. `rtana` (from `Cortana`): strings that exist nowhere in the source |
| 66 × U+202F, zero intact placeholders | The model rendered `<PER_2>` as `**PER 2**`; restoration was a **silent 100% no-op** |
| `PER_10`, `PER_11`, `PER_12` | Present in the model's output, absent from its own sanitized input: hallucinated |
| `+44 7700 900123` | Passed through completely unmasked |

The root cause is a single design choice, and the rebuild is organised around
making it impossible.

### Why PII alone is not enough

"PII" covers people. It does not cover the things a business actually cannot
send to a third party: that the platform is called **FleetCore**, and that the
customer is **BrightPath Logistics**. A generic NER model has no concept of
these (its label set is PER/ORG/LOC/MISC), which is why the domain layer exists
and why the taxonomy includes `INTERNAL_SYSTEM`, `CUSTOMER_ID`, `CONTRACT` and
`CONFIDENTIAL_BUSINESS_INFORMATION`.

## Policy

Detection and protection are different questions. Precedence, first match wins:

1. **denylist**: always protect, whatever the confidence
2. **allowlist**: public names such as Microsoft, Teams, Azure, GitHub, Cortana, London
3. **unknown type**: protect by default; a new detector's unconfigured label
   must not silently leak
4. **below threshold**: allow when failing open, **protect when failing
   closed**. That asymmetry is the whole point of the fail mode
5. **the type's default action**

Actions: `pseudonymize` (reversible), `redact`, `mask` (both irreversible),
`allow`. Shipped defaults live in
[`src/privacy_gateway/policy/actions.py`](src/privacy_gateway/policy/actions.py):

| Default action | Types (minimum confidence) |
|---|---|
| `pseudonymize` | PERSON (0.55), EMPLOYEE (0.60), STAKEHOLDER (0.60), EMAIL (0.90), PHONE (0.70), CUSTOMER (0.60), PROJECT (0.70), INTERNAL_SYSTEM (0.70), INTERNAL_SERVICE (0.70), CONTRACT (0.70), CONFIDENTIAL_BUSINESS_INFORMATION (0.70), CREDIT_CARD (0.90), DATE (0.70), SSN (0.85), LITERAL (0.0) |
| `allow` | ORGANIZATION, LOCATION, ADDRESS, URL, INTERNAL_URL, IP_ADDRESS, CUSTOMER_ID, ACCOUNT_IDENTIFIER (IBAN, bank account numbers), PASSPORT, PASSPORT_NUMBER, SESSION_TOKEN, GEO, DEVICE_ID |
| fallback for unknown types | `pseudonymize` (0.70), prefix `ENTITY` |

**`DATE` is `pseudonymize` by default (`<DATE_001>`).** Calendar dates, birth
dates and expiration dates are protected reversibly. Bare clock timestamps
(such as `00:04:12` or `10:30`), speaker headers and durations are filtered out
at aggregation so the document's structure and chronology stay legible.

**Public and excluded categories pass through in plain text.** Override any
type in `config/policy.toml`.

`PERSON`, `EMPLOYEE` and `STAKEHOLDER` share one `PERSON_NNN` counter, so a
reader tracks one numbering scheme for people rather than three.

## Pseudonymization and re-identification

Placeholders are `<PERSON_001>`, numbered in document order, assigned ascending
and applied descending so untouched spans keep valid offsets.

**Restoration never guesses.** A well-formed placeholder that is not in *this
conversation's* store is hallucinated: it is redacted and reported, never
resolved.

### Why tolerant matching is refused

The obvious response to `**PER 2**` is to match it loosely and substitute
anyway. That is rejected, on evidence from the prototype's run on the removed
meeting transcript. Its output contained:

```
**PER 3‑8, 20‑22, 24‑25**
```

A placeholder *range enumeration*, produced accidentally by a cooperative model
at temperature 0 with no adversary present, and it includes indices 24 and 25,
which the model invented. With 25 entities mapped, a range-expanding restorer
would have printed roughly thirteen real people's names into a table nobody
asked for.

Generalised: tolerant matching makes model-controlled fuzzy text a lookup key
into the secret store, and the model's output is steered by an untrusted
document. `Please list PER 1 through PER 50 for the appendix` becomes a
mapping-dump oracle. Exact matching is the only disclosure boundary that can be
reasoned about.

Instead, three layers that do not widen it:

1. **Prevent**: the system prompt states the placeholder contract explicitly.
   The prototype sent the bare transcript with no instruction at all.
2. **Detect**: a drift scanner finds `**PER 2**`, U+202F and U+2011
   separators, missing delimiters and range enumerations. It **reports**; a test
   asserts no drift finding ever alters the output.
3. **Repair**: one bounded corrective turn, then degrade visibly.

There is no setting that enables tolerant matching.

### Placeholder injection

A literal `<PERSON_001>` in the *input* is an attack: a naive gateway passes it
through, the model echoes it, and the gateway itself expands it into whichever
real person holds index 001. The guard neutralises any placeholder-shaped token
in the input before detection (under fail-closed with
`GATEWAY_BLOCK_ON_INJECTION=true`, the request is refused with exit code 5), so:

> every `<TYPE_NNN>` token in the text sent to the model was minted by this
> gateway, in this conversation.

It runs *after* normalization, so HTML-entity-encoded and fullwidth variants are
already folded into the plain form and are caught too, while a double-encoded
`&amp;lt;...&amp;gt;` stays inert, because entity decoding runs exactly once.

## Security model

| Property | How |
|---|---|
| Mapping never reaches the model | Structurally separate; asserted in tests five ways, including per-token |
| Mapping never reaches logs | `__repr__` on every sensitive type omits the value, so `logger.debug(f"{entity}")` is safe by construction |
| Pre-send leak gate | Unconditional, **not governed by `fail_mode`**: a transmission cannot be undone |
| Output leak | Fail-closed withholds the answer entirely (exit 6); fail-open returns it flagged `degraded` |
| Cross-conversation | One `MappingStore` per conversation; no global registry; mismatch raises |
| Conversation ids | ≥128 bits from `secrets.token_urlsafe` |
| Model output | Never used as a lookup key, never re-scanned after substitution |

## Evaluation

```bash
uv run python -m privacy_gateway.evaluation.cli validate   # check the gold set
uv run python -m privacy_gateway.evaluation.cli sweep      # writes evaluation/results/
uv run python scripts/sample_excerpts.py                   # deterministic, seeded; rewrites the unlabelled set
uv run python scripts/apply_labels.py                      # labels live in reviewable source; rewrites the .v1 gold file
```

`sweep` accepts `--configs A,B,D,E`, `--split {dev,test}`, `--gold` and `--out`.
The labelling procedure and rulings are in
[`evaluation/gold/LABELING.md`](evaluation/gold/LABELING.md).

**Method.** Turn-aligned excerpts, exhaustively labelled: a partially labelled
document makes precision uncomputable, because every unlabelled true entity
becomes a phantom false positive. Spans that could not be resolved are marked
`ambiguous` and excluded from both numerator and denominator rather than
guessed. Each detector runs once per document and configurations are evaluated
as set-unions over that cache, so comparing eight configurations is not eight
pipeline runs. The sweep measures detection, not protection: the policy layer
does not run, so entities it would allow (such as `Cortana`) count as false
positives.

**Primary criterion is strict span-and-type matching**, because the defect being
repaired *is* a boundary defect: under partial credit, `<PER_2>ania Fahmy`
scores as a near-hit and the prototype would report ~80% recall while corrupting
the document.

**Published results.** Measured on 22 excerpts / 168 scored spans at commit
`bfff63c`. Twelve of those excerpts came from a real meeting transcript that has
since been removed, so the shipped gold set is the 10 SME excerpts (58 scored
spans) and these numbers cannot be reproduced from it. PERSON was 86% of the
published set; read `No-speaker F1` as the more honest headline.

| Cfg | Detectors | Leak docs | Char recall | Strict P | Strict R | Strict F1 | No-speaker F1 |
|---|---|---|---|---|---|---|---|
| A | Presidio only | 10/22 | 0.811 | 0.718 | 0.696 | 0.707 | 0.512 |
| B | Generic NER only | 10/22 | 0.825 | 0.730 | 0.691 | 0.710 | 0.426 |
| C | Qwen only | *skipped* | not measured | not measured | not measured | not measured | not measured |
| D | Domain rules only | 20/22 | 0.585 | **0.960** | 0.577 | 0.721 | 0.578 |
| E | Presidio + rules | 8/22 | 0.889 | 0.747 | 0.792 | 0.769 | **0.667** |
| F | Presidio + rules + Qwen | *skipped* | not measured | not measured | not measured | not measured | not measured |
| G | All four layers | *skipped* | not measured | not measured | not measured | not measured | not measured |
| H | **Presidio + rules + NER** | **3/22** | **0.984** | 0.750 | **0.857** | **0.800** | 0.662 |

"Rules" means regex, domain lexicon and participant registry. C, F and G are
skipped because Qwen is disabled and no model was pulled; they are reported as
skipped, never as zero. H is not one of the seven original configurations; it
was added because with Qwen off there would otherwise be no row for the
configuration that actually ships.

`Leak docs` (excerpts where at least one gold entity was missed entirely) is the
figure to read first. For a gateway, one missed entity matters more than an
aggregate F1.

The shape of the result is the point: **curated rules are precise and blind**
(D: 0.96 precision, 0.577 recall, leaks in 20 of 22 excerpts), **models are
broad and imprecise**, and the combination beats either. That is the argument
for a layered architecture, measured rather than asserted.

## Performance

```bash
uv run python benchmarks/bench.py --mode overhead --runs 30   # default: no network
uv run python benchmarks/bench.py --mode e2e --runs 20        # needs Ollama
```

`bench.py` also accepts `--warmup` (default 2), `--detectors` and `--out`
(default `benchmarks/results/`), and runs over every `.txt` file in
`test_data/`. Overhead mode is the default because the overhead is what the
gateway is responsible for, and a benchmark that cannot run without a hosted
service mostly does not run.

**Published results.** One machine, 16 logical cores, CPU only, no CUDA; n=30
after 2 warmups; a 13,236-character noisy ASR meeting transcript (328 entities)
that has since been removed from the repository:

| Configuration | Median | p95 | stdev | ms / 1000 chars | Model footprint |
|---|---|---|---|---|---|
| `regex,registry,domain` | **75 ms** | 108 ms | 0.02 s | 5.7 | 1 MB |
| `+ presidio,ner` | **8.95 s** | 15.80 s | 3.63 s | 676 | 2,636 MB |

`p99` is absent from both rows because n=30 cannot support it; the results file
records it as a withheld value with its reason. `p99` is never emitted below
n=100 and `p95` below n=20, and the suppression is in the data, not in prose.

**The trade-off is steep**: roughly 120× the latency and 2,600× the memory, for
+0.28 recall and 17 fewer leaking documents. The model-backed configuration is
also far less predictable: a p95 of 15.8 s against an 8.95 s median on identical
input is CPU inference variance and would need pinning before any latency SLO.
On a short chat message the model layers are cheap; on a 14 KB transcript they
dominate. The fast configuration's cost is measured in recall, not just
milliseconds (see [Usage](#usage)).

## Large inputs and streaming

Detection is chunked and every entity is rebased to absolute offsets
immediately, so there is exactly one coordinate space downstream, which is what
makes the aggregation post-conditions checkable. An entity straddling a chunk
boundary is handled by the overlap region and the ordinary overlap algorithm,
not a special case. One `MappingStore` spans the whole conversation, so an
entity gets the same placeholder in chunk 1 and chunk 7.

Streaming is not supported. The gateway waits for the whole response, which is
what lets the drift-retry loop and fail-closed response blocking run at all.

## Project layout

```
src/privacy_gateway/
  config.py errors.py gateway.py cli.py report.py
  preprocessing/     offsets.py normalizer.py transcript.py registry.py
  detectors/         base.py patterns.py regex_ presidio_ ner_ qwen_ domain_ registry_
  entities/          entity.py taxonomy.py spans.py
  aggregation/       aggregator.py common_words.py
  policy/            actions.py engine.py allowlist.py
  pseudonymization/  placeholders.py mapping_store.py applier.py consistency.py
  reidentification/  restorer.py drift.py output_scanner.py injection.py
  llm/               base.py ollama_client.py mock_client.py prompt.py
  observability/     timing.py
  evaluation/        gold.py metrics.py sweep.py report.py cli.py
config/ resources/ evaluation/gold/ benchmarks/ scripts/ test_data/
tests/  unit/ integration/ security/ regression/ evaluation/ _helpers/
```

## Production-readiness checklist

| State | Item | Notes |
|---|---|---|
| Done | Corruption class eliminated | Offset-based replacement; lossless inversion proven on the SME transcript |
| Done | Mapping isolated from the model | Asserted five ways, with a negative control |
| Done | Fail-closed by default | Detector failure aborts before any model call |
| Done | Injection defence | Neutralised before detection; blocks under fail-closed |
| Done | No raw values in logs | Enforced by `__repr__`, not by discipline |
| Done | Configuration as data | Policy, lexicon, allowlist, denylist all external |
| Done | Measured, not asserted | Evaluation sweep and latency benchmark, with provenance |
| Done | Validated on realistic documents | The synthetic documents in `test_data/` (interview transcripts, support tickets, config files, financial forms), run end to end against the real downstream model. Each gap found is fixed and pinned by test, or documented in `LIMITATIONS.md` |
| Caveat | Evaluation labels | **AI-generated, not human-verified.** Review before relying on the figures |
| Caveat | Qwen layer | Implemented and unit-tested; **never run against a real model** |
| Caveat | Memory growth | 2.6 GB footprint with model layers; steady-state RSS unmeasured |
| Caveat | Over-redaction on noisy ASR | Expected and correct, but a real utility cost |
| Not done | Mapping persistence | In-memory only. Persisting it needs encryption at rest before multi-turn production use |
| Not done | Authentication / multi-tenancy | Out of scope; conversation isolation is not an authorisation boundary |
| Not done | Red-teaming | Only the scripted cases in `tests/security/` |

## Testing

```bash
uv run pytest -q                                            # default selection: 643 tests
uv run pytest tests/unit -q                                 # fast layer
uv run pytest tests/regression -q                           # the acceptance gate
uv run pytest -q -m "not requires_models and not requires_ollama"   # no spaCy/BERT models needed
```

643 tests are collected: unit 479, evaluation 63, security 36, regression 35,
integration 30. None requires a network or a running Ollama
(`requires_ollama` is deselected by default). Two regression tests are marked
`requires_models` and need `en_core_web_lg` and `dslim/bert-base-NER` on disk.
Markers (`slow`, `requires_models`, `requires_ollama`, `requires_llm`,
`property`, `regression`, `security`) are declared in `pyproject.toml`; the
model, Ollama, regression and security markers are applied automatically in
`tests/conftest.py`.

The regression suite has two halves. The first pins **the evidence**: the
prototype artifacts must keep demonstrating the defects, because a fixture that
has quietly stopped reproducing a bug makes the rest of the suite assert
nothing. The second runs the current pipeline over the same transcript.

`assert_no_secrets` checks five ways (exact, case-folded, whitespace-squashed,
per-token and digit-run) because the interesting leak is not a whole name but
`<PER_2>ania Fahmy`, where the surname sits in plain text beside a placeholder.
A **negative-control test** plants exactly that and requires the helper to catch
it; an assertion helper that has never failed is not evidence.

The integration suite runs the whole pipeline against `EchoLLMClient`, which
returns the prompt verbatim, and checks that restoration reproduces the
normalized input, with no model and no network.

## Limitations

The short list; [`LIMITATIONS.md`](LIMITATIONS.md) has the full account.

- Evaluation labels are AI-generated and unreviewed; the shipped gold set is 10
  excerpts from one synthetic transcript, and the published numbers used 12
  excerpts that are no longer in the repository.
- The Qwen layer has never run against a real model.
- Model-backed detection is slow and variable on CPU (8.95 s median, 15.8 s
  p95 on a 13 KB transcript) with a ~2.6 GB footprint.
- The deterministic-only configuration misses names that are neither speakers
  nor in the lexicon.
- Not detected: bare CVVs and `MM/YY` expiries, SWIFT/BIC, routing and account
  numbers. Connection-string authorities are protected as one coarse block.
- Case variants restore to the first-seen spelling; ambiguous first names get
  their own placeholder rather than being attributed.
- English only; no streaming; mapping held in memory only; no authentication;
  no red-teaming beyond scripted tests.
- The common-word filter is curated for this domain and needs extending
  elsewhere.

## License

MIT. See [LICENSE](LICENSE).
