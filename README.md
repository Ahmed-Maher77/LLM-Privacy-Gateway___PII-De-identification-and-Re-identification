# PII De-identification and Re-identification Implementations

Six independent implementations of the same idea: find personally identifiable
information (PII) in text such as meeting and support transcripts, and replace it
before the text reaches a language model or leaves the machine. Each one is a
self-contained project with its own README, setup and tests. Folder names give
the language and the main detection technologies.

| Folder | Language | Approach | Restores originals |
| --- | --- | --- | --- |
| [`01-python-gliner-spacy-gateway`](01-python-gliner-spacy-gateway) | Python | LLM privacy gateway: regex patterns, GLiNER and spaCy NER, a speaker roster and a title lexicon, with two fail-closed verification passes before text is sent | Yes |
| [`02-ts-lists-transformersjs-ner`](02-ts-lists-transformersjs-ner) | TypeScript | Pre-defined lists plus a local Transformers.js NER model, fully in-process | No (one-way redaction) |
| [`03-ts-winknlp-regex-rules-poc`](03-ts-winknlp-regex-rules-poc) | TypeScript | Proof of concept measuring what WinkNLP can detect, combined with regex and anchored rules | Yes (numbered placeholders) |
| [`04-ts-multilayer-lists-regex-ner-winknlp`](04-ts-multilayer-lists-regex-ner-winknlp) | TypeScript | Multi-layer pipeline: pre-defined lists and name registries, regex, Transformers.js NER and wink-nlp | No (one-way redaction) |
| [`05-python-presidio-bert-qwen-gateway`](05-python-presidio-bert-qwen-gateway) | Python | LLM privacy gateway: regex, participant registry, domain lexicon, Presidio, BERT NER and an optional Qwen detector, with policy, re-identification and an evaluation harness | Yes |
| [`06-ts-winknlp-lite`](06-ts-winknlp-lite) | TypeScript | Lightweight wink-nlp pipeline for emails, URLs, dates and similar entities | No (one-way redaction) |

All test data in these projects is synthetic.

## Clone

Each implementation is a git submodule whose history lives on a branch of this
same repository, named like its folder (for example `01-python-gliner-spacy-gateway`),
so every submodule URL is the relative `./`.

```sh
git clone --recurse-submodules https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification.git
```

In an existing clone, run `git submodule update --init`.

## Work inside a submodule

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
