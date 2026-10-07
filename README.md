# PII De-identification and Re-identification Implementations

Each implementation is a git submodule. Its history lives on a branch of this
same repository, so every submodule URL is the relative `./`.

| Folder | Branch | Project |
| --- | --- | --- |
| `implementation_1` | `implementation_1` | LLM Privacy Gateway: PII De-identification and Re-identification (Python) |
| `implementation_2` | `implementation_2` | PII Detection & Redaction Pipeline |
| `implementation_3` | `implementation_3` | WinkNLP PII Detection Proof of Concept |
| `implementation_4` | `implementation_4` | PII Detection & Redaction Pipeline |
| `implementation_5` | `implementation_5` | LLM Privacy Gateway & PII De-identification Suite |
| `implementation_6` | `implementation_6` | WinkNLP PII Redaction Pipeline |

## Clone

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
