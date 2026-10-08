# Cross-implementation benchmark

Runs all six implementations on the same document, on the same machine, so
their protection, speed and memory can be compared directly. Each project's own
README reports numbers measured on its own data; those are not comparable with
each other. This is.

## What it measures

`sample.txt` is a synthetic support-case bundle (a call transcript, an email, a
ticket form and an application log) that none of the projects was developed or
tuned on. `labels.json` lists 28 sensitive values in it, by category, and ten
ordinary terms that should survive.

| Column | Meaning |
| --- | --- |
| Protected | Labelled values that no longer appear verbatim in the output |
| Leaked | Labelled values still present verbatim |
| Partial names | Full names not leaked whole, but with one of their words still visible |
| Over-redacted | Ordinary terms from the `keep` list that were masked |
| Cold start | Process start to the first result, including module and model loading |
| Warm / doc | Median time per document over the following runs |
| Memory | Resident set size after the runs |

A "leak" is measured against this file's labels, not against each project's
policy. Several projects leave some categories in plain text **by design**
(for example, organizations, IP addresses or URLs), and one only targets names
and companies; read the per-category results before ranking them.

## Running it

Install each implementation first, as its README describes (Python projects
need their `.venv`, TypeScript projects their `node_modules`, and the NER
models fetched where a project uses one). Then, from the repository root:

```sh
python benchmark/run.py            # all six, 5 warm runs each
python benchmark/run.py --only 03,06 --runs 10
```

Each implementation is called in-process through a small adapter in
`adapters/` that uses the same configuration as the project's own CLI. Results
are written to `benchmark/results/` (one JSON per implementation, with the
sanitized text and the per-category leaks, plus `summary.md`).
