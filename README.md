# PII De-identification and Re-identification Implementations

Six independent implementations of the same idea: find personally identifiable
information (PII) in text such as meeting and support transcripts, and replace it
before the text reaches a language model or leaves the machine. Each one is a
self-contained project with its own README, setup and tests.

| Folder | Language | Approach | Restores originals |
| --- | --- | --- | --- |
| [`implementation_1`](implementation_1) | Python | LLM privacy gateway: regex patterns, GLiNER and spaCy NER, a speaker roster and a title lexicon, with two fail-closed verification passes before text is sent | Yes |
| [`implementation_2`](implementation_2) | TypeScript | Pre-defined lists plus a local Transformers.js NER model, fully in-process | No (one-way redaction) |
| [`implementation_3`](implementation_3) | TypeScript | Proof of concept measuring what WinkNLP can detect, combined with regex and anchored rules | Yes (numbered placeholders) |
| [`implementation_4`](implementation_4) | TypeScript | Multi-layer pipeline: pre-defined lists and name registries, regex, Transformers.js NER and wink-nlp | No (one-way redaction) |
| [`implementation_5`](implementation_5) | Python | LLM privacy gateway: regex, participant registry, domain lexicon, Presidio, BERT NER and an optional Qwen detector, with policy, re-identification and an evaluation harness | Yes |
| [`implementation_6`](implementation_6) | TypeScript | Lightweight wink-nlp pipeline for emails, URLs, dates and similar entities | No (one-way redaction) |

All test data in these projects is synthetic.

## Clone

Each implementation is a git submodule whose history lives on a branch of this
same repository (`implementation_1` … `implementation_6`), so every submodule
URL is the relative `./`.

```sh
git clone --recurse-submodules https://github.com/Ahmed-Maher77/LLM-Privacy-Gateway___PII-De-identification-and-Re-identification.git
```

In an existing clone, run `git submodule update --init`.

## Work inside a submodule

```sh
cd implementation_2
git switch implementation_2      # submodules check out detached by default
# edit, commit
git push origin HEAD:implementation_2
cd ..
git add implementation_2         # record the new submodule commit
git commit -m "Bump implementation_2"
```

To pull the latest commit of every branch: `git submodule update --remote`.
