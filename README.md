# PII De-identification and Re-identification Implementations

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB.svg)
![Node.js 20.9+](https://img.shields.io/badge/node.js-20.9%2B-339933.svg)
![TypeScript](https://img.shields.io/badge/typescript-strict-3178C6.svg)

Six independent implementations of one idea: find personally identifiable
information (PII) in text such as meeting transcripts, support tickets and logs,
and replace it before the text reaches a large language model (LLM) or leaves
the machine. Two of them also put the original values back into the model's
answer.

They span the whole design space, from a 5 MB rule-based library that answers in
milliseconds to multi-model gateways with fail-closed verification. This README
compares them side by side, with a shared benchmark, and shows how to install and
run each one.

- **De-identification**: detect sensitive values and replace them, for example
  `Sarah Johnson` → `<PERSON_1>`.
- **Re-identification**: map the placeholders in the LLM's response back to the
  original values, using a mapping that never leaves the process.

## Contents

- [The implementations](#the-implementations)
- [Which one should I use?](#which-one-should-i-use)
- [Comparison](#comparison)
  - [Architecture and safety](#architecture-and-safety)
  - [What gets protected](#what-gets-protected)
  - [Head-to-head benchmark](#head-to-head-benchmark)
  - [Dependencies, models and footprint](#dependencies-models-and-footprint)
  - [Published accuracy and speed](#published-accuracy-and-speed)
  - [Engineering and maturity](#engineering-and-maturity)
  - [Strengths and trade-offs](#strengths-and-trade-offs)
- [Getting started](#getting-started)
- [Running the benchmark](#running-the-benchmark)
- [Repository layout](#repository-layout)
- [Working with the submodules](#working-with-the-submodules)
- [A note on data](#a-note-on-data)
- [License](#license)

## The implementations

| # | Folder | Language | In one line | Reversible |
| --- | --- | --- | --- | --- |
| 01 | [`01-python-gliner-spacy-gateway`](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/tree/01-python-gliner-spacy-gateway) | Python | LLM privacy gateway: regex patterns, GLiNER + spaCy NER, speaker roster and title lexicon, with two fail-closed verification passes | Yes |
| 02 | [`02-ts-lists-transformersjs-ner`](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/tree/02-ts-lists-transformersjs-ner) | TypeScript | Names and listed companies only: pre-defined lists plus a local BERT NER model through Transformers.js | No |
| 03 | [`03-ts-winknlp-regex-rules-poc`](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/tree/03-ts-winknlp-regex-rules-poc) | TypeScript | Proof of concept: what WinkNLP can and cannot detect, combined with regex and anchored person rules | Yes (numbered mode) |
| 04 | [`04-ts-multilayer-lists-regex-ner-winknlp`](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/tree/04-ts-multilayer-lists-regex-ner-winknlp) | TypeScript | Four layers: pre-defined lists and open name registries, checksum-validated regex, BERT NER and wink-nlp | No |
| 05 | [`05-python-presidio-bert-qwen-gateway`](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/tree/05-python-presidio-bert-qwen-gateway) | Python | LLM privacy gateway: regex, participant registry, domain lexicon, Presidio, BERT NER and optional Qwen; policy engine, exact restoration with drift detection, evaluation harness | Yes |
| 06 | [`06-ts-winknlp-lite`](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/tree/06-ts-winknlp-lite) | TypeScript | Minimal wink-nlp masker for emails, URLs, dates and similar web entities | No |

Each folder is a self-contained project with its own README, setup, tests and
license; this file is the map.

## Which one should I use?

| If you need | Use | Why |
| --- | --- | --- |
| The broadest protection before an LLM call, and you can afford seconds per document | **01** | Highest score in the shared benchmark (25 of 28 values protected); covers financial, government, network and secret-shaped identifiers; refuses to send text that fails verification |
| A full LLM gateway with policy, business-confidential terms and safe restoration | **05** | Policy layer (protect vs allow per type), domain lexicon for internal systems, customers and projects, exact-match restoration with drift detection, evaluation harness |
| One-way redaction of support transcripts in Node.js, offline, with good name recall | **04** | Names, contact details, cards, IBANs, SSNs and US IDs; strong on lowercase speech-to-text; no services, no network at run time |
| Only people's and companies' names masked, with the rest left readable | **02** | Deliberately narrow scope; your lists are always applied; small model (29 MB) |
| Sub-millisecond, dependency-light masking with reversible placeholders | **03** | About 5 MB at run time, two dependencies, deterministic rules for structured identifiers, numbered placeholders that can be unmasked |
| A tiny first-pass filter for emails, URLs and dates | **06** | Smallest and simplest; detects only what the wink-nlp lite model recognizes |

None of them is a certified anonymization product. Every project documents its
limitations; read them before relying on one for real data.

## Comparison

### Architecture and safety

| | 01 | 02 | 03 | 04 | 05 | 06 |
| --- | --- | --- | --- | --- | --- | --- |
| Rule-based detection | Regex with graded checksums, secrets, IDs | Pre-defined lists | Regex, anchored name rules, caller lists | Lists, name registries, regex with checksums | Regex, participant registry, domain lexicon | — |
| Statistical / ML detection | GLiNER (multilingual) + spaCy | BERT NER (Transformers.js) | WinkNLP built-in entities | BERT NER + wink-nlp | Presidio (spaCy) + BERT NER; optional Qwen LLM | wink-nlp |
| Overlap resolution | Span resolver with label voting | Merge (union) | Normalizer (enclosing span wins) | Merge (union) | Aggregator with asserted invariants | Merge (union) |
| Placeholder style | `{{PERSON_1}}` | `<PERSON_1>` | `[PERSON]` or `[PERSON_1]` | `<PERSON_1>` | `<PERSON_001>` (configurable) | `[EMAIL]` |
| Same value → same placeholder | Yes | Yes | Yes (numbered mode) | Yes | Yes | No (generic) |
| Re-identification | `restore_for()` from an in-memory vault | — | `unmaskPII()` | — | Exact-match restore, drift scan, one corrective retry | — |
| Safety gate before sending | Two passes (`audit` + residual secret scan); fail-closed | Fail-closed on load/offset errors | — | Fail-closed on load/offset errors | Pre-send leak gate, output scan, fail-closed mode | — |
| LLM integration | Ollama (`langchain-ollama`) | — | — | — | Ollama, plus offline `echo`/`mock` providers | — |
| Interface | CLI + Python library | CLI + TS library | npm scripts + TS library | CLI + TS library | CLI + Python library | Script + TS library |

### What gets protected

Default configuration of each project. "Listed" means only values you put in a
configuration list; "allowed" means detected but deliberately left in plain text
by the default policy.

| PII type | 01 | 02 | 03 | 04 | 05 | 06 |
| --- | --- | --- | --- | --- | --- | --- |
| Person names | Yes | Yes | Anchored or listed | Yes | Yes | — |
| Organizations | `strict` profile | Listed | Listed (opt-in) | Listed | Allowed | — |
| Business terms (systems, customers, projects) | Custom patterns | — | — | Listed | Yes (domain lexicon) | — |
| Email | Yes | — | Yes | Yes | Yes | Yes |
| Phone | Yes | — | Yes | Yes | Yes | — |
| Payment card | Yes | — | Yes | Yes | Yes | — |
| IBAN / bank account | Yes | — | — | IBAN | Allowed | — |
| SSN / national ID | Yes | — | SSN | SSN, US passport, US driver licence | SSN | — |
| Date of birth / dates | DOB | — | Opt-in | Yes | Yes | Yes |
| Postal address | Yes | — | US | — | Allowed | — |
| IP / MAC address | Yes | — | IPv4 | — | Allowed | — |
| URL | Yes | — | Yes | — | Allowed | Yes |
| Secrets (credentials, tokens, connection strings) | Yes | — | — | — | Yes | — |
| Language | Multilingual model; English heuristics | English | English | English | English | English |

### Head-to-head benchmark

Each implementation's own README reports numbers measured on its own data, which
cannot be compared with each other. The [`benchmark/`](benchmark) folder runs all
six on **the same new, synthetic document** that none of them was developed or
tuned on: a support-case bundle with a call transcript, an email, a ticket form
and an application log, containing 28 labelled sensitive values and ten ordinary
terms that should survive.

**Values protected** (labelled values that no longer appear in the output):

| | 01 | 02 | 03 | 04 | 05 | 06 |
| --- | --- | --- | --- | --- | --- | --- |
| **Protected (of 28)** | **25** | 7 | 19 | 20 | 18 | 7 |
| Person names (8) | 7 | 7 | 5 | 7 | 7 | 0 |
| Email (4) | 4 | 0 | 4 | 4 | 4 | 4 |
| Phone (3) | 3 | 0 | 2 | 2 | 2 | 0 |
| Date of birth (2) | 1 | 0 | 2 | 2 | 2 | 2 |
| Payment card (1) | 1 | 0 | 1 | 1 | 1 | 0 |
| IBAN (1) | 1 | 0 | 0 | 1 | 1 | 0 |
| SSN (1) | 1 | 0 | 1 | 1 | 1 | 0 |
| Postal address (1) | 1 | 0 | 1 | 0 | 0 | 0 |
| Organization (1) | 0 | 0 | 0 | 0 | 0 | 0 |
| Customer / account IDs (2) | 2 | 0 | 0 | 0 | 0 | 0 |
| Passport number (1) | 1 | 0 | 0 | 1 | 0 | 0 |
| IP address (2) | 2 | 0 | 2 | 1 | 0 | 0 |
| URL (1) | 1 | 0 | 1 | 0 | 0 | 1 |
| Ordinary terms wrongly masked (of 10) | 0 | 0 | 0 | 0 | 2 | 2 |

Read this together with [What gets protected](#what-gets-protected): several
"leaks" are deliberate. 02 masks only names and companies by design; 05 allows
organizations, addresses, IP addresses, URLs, customer IDs and passports by
default policy; the organization in the document is not on any project's list.
The one name most of them miss is written entirely in lower case, as speech-to-text
produces it. The two "ordinary terms" masked by 05 and 06 are the weekdays
"Monday" and "Thursday", treated as dates.

**Speed and memory** on the same document (2.1 KB):

| | 01 | 02 | 03 | 04 | 05 | 06 |
| --- | --- | --- | --- | --- | --- | --- |
| Cold start (first result, incl. model loading) | 104 s | 4.4 s | 1.7 s | 18.5 s | 33 s | 5.4 s |
| Warm, per document | 14.4 s | 0.37 s | 6 ms | 0.18 s | 9.6 s | 13 ms |
| Memory (RSS) | 2.5 GB | 0.34 GB | 0.11 GB | 0.41 GB | 1.6 GB | 0.11 GB |

Measured on an 11th-gen Intel Core i7-11850H (8 cores / 16 threads, 32 GB RAM),
Windows 11, CPU only, Node.js 22.19, Python 3.12; warm time is the median of 5
runs (2 for 05). These runs shared the CPU with other work, so absolute times are
inflated, the model-backed projects most; the order of magnitude and the ranking
are the meaningful part. First-run model downloads are not included. Reproduce
on your own hardware with [`python benchmark/run.py`](#running-the-benchmark).

### Dependencies, models and footprint

| | 01 | 02 | 03 | 04 | 05 | 06 |
| --- | --- | --- | --- | --- | --- | --- |
| Runtime | Python 3.12+, uv | Node.js 20.9+, npm | Node.js 22.12+, npm | Node.js 20.9+, npm | Python 3.12+, uv | Node.js 22+, npm |
| Key libraries | gliner, spacy, torch, transformers, langchain-ollama | @huggingface/transformers, dotenv | wink-nlp | @huggingface/transformers, wink-nlp, libphonenumber-js | presidio, spacy, torch, transformers, langchain-ollama | wink-nlp |
| Models | GLiNER `urchade/gliner_multi_pii-v1` (~1.16 GB), spaCy `en_core_web_lg` (~425 MB) | `gravitee-io/bert-small-pii-detection` (29 MB, ONNX) | `wink-eng-lite-web-model` (3.8 MB, bundled) | Same BERT model (29 MB) + 7 MB name/place lists | spaCy `en_core_web_lg` (~425 MB), `dslim/bert-base-NER` (~415 MB); optional Qwen 2.5 7B via Ollama | `wink-eng-lite-web-model` (3.8 MB, bundled) |
| Install size | ~2.6 GB (1.4 GB `.venv` + model cache) | ~560 MB | 89 MB (~5 MB at run time) | ~565 MB | ~1.8 GB (1.4 GB `.venv` + model cache) | 50 MB (~5 MB at run time) |
| Network | Model download on first run; LLM step via Ollama | Install + one-time model fetch | Install only | Install + one-time model fetch | Model download on first run; `run` via Ollama | Install only |

### Published accuracy and speed

Each project's own measurements, on its own (synthetic) data. They are not
comparable across projects; see each README for the method and caveats.

| | Accuracy (own data) | Speed (own data) |
| --- | --- | --- |
| [01](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/blob/01-python-gliner-spacy-gateway/README.md#evaluation) | P / R / F1 = 1.00 on its tuned 37-document corpus (precision is a lower bound); 62 of 64 held-out checks pass | Cold start 21.6 s; p50 0.82 s per document, 15 s for 8 KB+ documents |
| [02](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/blob/02-ts-lists-transformersjs-ner/README.md#measured-numbers) | 98.5% of names and companies found, 98.2% precision (10 transcripts) | 6 KB: 0.93 s cold, 0.19 s warm, 0.30 GB |
| [03](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/blob/03-ts-winknlp-regex-rules-poc/README.md#evaluation-results) | P 100% / R 75.9% / F1 86.3% (20 cases, 29 entities); 90.9% F1 with known names | ~0.1–0.3 ms per short document |
| [04](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/blob/04-ts-multilayer-lists-regex-ner-winknlp/README.md#measured-numbers) | 99.1% of PII found, 98.6% precision (10 transcripts) | 6 KB: 1.4 s cold, 0.19 s warm, 0.45 GB |
| [05](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/blob/05-python-presidio-bert-qwen-gateway/README.md#evaluation) | Shipped configuration: strict F1 0.80, character recall 0.984, 3 of 22 excerpts leaking (AI-generated labels; not reproducible from the shipped gold set) | 13 KB: 75 ms rules only; 8.95 s with model layers |
| [06](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/tree/06-ts-winknlp-lite) | Not published | Not published |

### Engineering and maturity

| | 01 | 02 | 03 | 04 | 05 | 06 |
| --- | --- | --- | --- | --- | --- | --- |
| Automated tests | 618 (pytest; 494 run without models) | Type check only | 60 (Vitest) | Regression, accuracy and offset checks | 643 (pytest) + ruff | 11 (node:test) |
| Evaluation tooling | Corpus scorer, held-out corpus, benchmark | — | Labelled evaluation, benchmark | `eval`, `check`, `bench` | Configuration sweep, gold set, benchmark | — |
| CI | GitHub Actions (Ubuntu + Windows) | — | — | — | — | — |
| Configuration | Profiles, per-entity overrides, fixed names, TOML patterns, env | Env + JSON lists | Options object | Env + JSON list | Env (30+ settings), lexicon, allow/deny lists, policy file | Options object |
| Status | Advanced prototype | Working CLI/library | Proof of concept | Working CLI/library | Advanced prototype | Prototype |

### Strengths and trade-offs

| | Strengths | Trade-offs |
| --- | --- | --- |
| **01** | Broadest coverage; two independent verification passes; structure-aware (JSON, code); injection defence; held-out evaluation | Heaviest: ~2.6 GB on disk and RAM, seconds per document on CPU |
| **02** | Small model; predictable, list-driven; offline at run time | Names and listed companies only; no unit tests |
| **03** | Tiny, fast, deterministic; reversible numbered placeholders; documents WinkNLP's real capabilities | No statistical name detection; names need conversational anchors or a list |
| **04** | Good coverage with a small model; strong on lowercase speech-to-text; fail-closed offset checks | One-way only; addresses, IPs and URLs not covered |
| **05** | Policy layer; business-confidential terms; safest restoration; measured design decisions | Heavy model layers; allows several categories by default; evaluation labels are AI-generated |
| **06** | Smallest and simplest; offline | Detects only emails, URLs, dates, times, money and mentions |

## Getting started

### Prerequisites

- **Git** with submodule support
- **Python projects (01, 05):** Python 3.12+ and [uv](https://docs.astral.sh/uv/);
  [Ollama](https://ollama.com/) only for the LLM round trip
- **TypeScript projects (02, 03, 04, 06):** Node.js (20.9+ for 02 and 04, 22.12+
  for 03, 22+ for 06) and npm

### Clone

```sh
git clone --recurse-submodules https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification.git
cd LLM-Privacy-Gateway___PII-De-identification-and-Re-identification
```

In an existing clone, run `git submodule update --init`.

### Install and run each implementation

Every command below runs from the repository root. Each project's README has the
full usage, configuration and library API.

**01 · GLiNER + spaCy gateway** ([README](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/blob/01-python-gliner-spacy-gateway/README.md))

```sh
cd 01-python-gliner-spacy-gateway
uv sync
uv run python -m spacy download en_core_web_lg
cp .env.example .env                                                             # optional
uv run python generate_report.py test_data/sme_meeting_transcript.txt --skip-llm   # anonymize + verify, no LLM
uv run python main.py                                                            # full round trip (needs Ollama)
```

**02 · Lists + Transformers.js NER** ([README](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/blob/02-ts-lists-transformersjs-ner/README.md))

```sh
cd 02-ts-lists-transformersjs-ner
npm install
npm run fetch:model            # once: downloads the 29 MB model
npm run dev test_data/test.txt # writes reports/test__sanitized.txt
```

**03 · WinkNLP + regex rules POC** ([README](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/blob/03-ts-winknlp-regex-rules-poc/README.md))

```sh
cd 03-ts-winknlp-regex-rules-poc
npm install
npm test                       # 60 tests
npm run demo                   # detect, mask and unmask a sample transcript
```

**04 · Multi-layer lists + regex + NER + wink-nlp** ([README](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/blob/04-ts-multilayer-lists-regex-ner-winknlp/README.md))

```sh
cd 04-ts-multilayer-lists-regex-ner-winknlp
npm install
npm run fetch:model                   # once: downloads the 29 MB model
npm run dev -- test_data/test_2.txt   # writes reports/test_2__sanitized.txt
```

**05 · Presidio + BERT + Qwen gateway** ([README](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/blob/05-python-presidio-bert-qwen-gateway/README.md))

```sh
cd 05-python-presidio-bert-qwen-gateway
uv sync --group dev --group models
uv run privacy-gateway sanitize test_data/sme_meeting_transcript.txt --detectors regex,registry,domain   # rules only, no models
uv run privacy-gateway sanitize test_data/sme_meeting_transcript.txt                                    # all default detectors
uv run privacy-gateway run test_data/sme_meeting_transcript.txt --print-answer                          # full round trip (needs Ollama)
```

**06 · WinkNLP lite** ([README](https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification/blob/06-ts-winknlp-lite/README.md))

```sh
cd 06-ts-winknlp-lite
npm install
npm run dev                    # masks test_data/mockup_interview.txt into reports/
```

## Running the benchmark

Install the implementations you want to compare (as above), then from the
repository root:

```sh
python benchmark/run.py                   # all six, 5 warm runs each
python benchmark/run.py --only 03,04,06   # a subset
```

The model-backed projects (01, 05) each need 2–3 GB of free memory; run them
separately on smaller machines. Results go to `benchmark/results/` (git-ignored):
one JSON file per implementation with the sanitized output and per-category
leaks, plus `summary.md`. The method is described in
[`benchmark/README.md`](benchmark/README.md).

## Repository layout

```
.
├── 01-python-gliner-spacy-gateway/          submodule (branch 01-python-gliner-spacy-gateway)
├── 02-ts-lists-transformersjs-ner/          submodule
├── 03-ts-winknlp-regex-rules-poc/           submodule
├── 04-ts-multilayer-lists-regex-ner-winknlp/ submodule
├── 05-python-presidio-bert-qwen-gateway/    submodule
├── 06-ts-winknlp-lite/                      submodule
├── benchmark/                               shared document, labels, adapters and runner
├── LICENSE
└── README.md
```

## Working with the submodules

Each implementation is a git submodule whose history lives on a branch of this
same repository, named like its folder. Every submodule URL is the relative
`../LLM-Privacy-Gateway___PII-De-identification-and-Re-identification.git`,
which resolves to this repository (or to your fork of it), and GitHub links each
folder to the pinned commit.

```sh
cd 02-ts-lists-transformersjs-ner
git switch 02-ts-lists-transformersjs-ner   # submodules check out detached by default
# edit, commit
git push origin HEAD:02-ts-lists-transformersjs-ner
cd ..
git add 02-ts-lists-transformersjs-ner      # record the new submodule commit
git commit -m "Bump 02-ts-lists-transformersjs-ner"
```

To pull the latest commit of every branch: `git submodule update --remote`.

## A note on data

All test data and the benchmark document are synthetic: names, emails, phone
numbers, card numbers, IBANs and addresses are invented or standard
documentation examples

## License

MIT — see [LICENSE](LICENSE). Each implementation carries the same license;
third-party models and data keep their own licenses (noted in each project).
