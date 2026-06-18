# Research Reproducibility

The publication pipeline uses Python 3.10 or newer and a repository-local
virtual environment. The exact direct dependencies used for the reported run
are pinned in `requirements-research.txt`.

Use Linux x86-64 for the complete 25-task CWEval evaluation. CWEval's
`cwe_1333_0` ReDoS security oracle depends on Linux x86-64 timing behavior; on
other platforms VibeGuard records its outcome as unavailable and writes the
excluded rows to `cweval_oracle_exclusions.csv` instead of treating them as
secure or insecure.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-research.txt
```

## Pinned Inputs

| Input | Revision |
|---|---|
| CWEval | `a279fd924f15cf2b45d8e9808c8e3c578de2d6d7` |
| SALLM | `b0db10f0cf1bf12e46751bfd0a8680d448c6151a` |
| SecurityEval | `d1b6f685bba97b6f14af5f256e2aebf44216261f` |
| Semgrep rules | `d4143379ff1307c410b4672a501f056be363ddd3` |
| HumanEvalPlus | release `v0.1.10` |

Expected local paths are `dataset/cweval`, `dataset/sallm`,
`dataset/securityeval`, `dataset/semgrep-rules`, and
`dataset/evalplus/HumanEvalPlus-v0.1.10.jsonl`. Downloaded inputs are ignored
by Git; the result manifest records their revisions.

## Model Sampling

The study requests five independent samples per CWEval task at temperature
0.2 from these immutable OpenAI snapshots:

- `gpt-4.1-2025-04-14`
- `gpt-4.1-mini-2025-04-14`
- `gpt-4o-2024-08-06`
- `gpt-4o-mini-2024-07-18`

Set `OPENAI_API_KEY` only in the process environment. Never place a key in a
repository file. Responses, response IDs, resolved model IDs, token usage, and
system fingerprints are cached under the ignored `data/cache` directory.
Once every required generation and repair response is cached, the pipeline can
be rerun without an API key. It fails before repair evaluation if a cache entry
is missing and no key is available.

## Run

```bash
OPENAI_API_KEY=... ./scripts/reproduce_paper.sh
```

The script reuses an existing generated or annotated corpus. It writes
per-sample outcomes, detection metrics, confidence intervals, paired tests,
ablation tables, model-level secure@k estimates, cross-dataset measurements,
and an environment manifest under `results/research_v4`.

The script also runs deterministic and LLM repair by default. Set
`WITH_LLM_REPAIR=0` to reproduce the detection and generation sections without
additional repair-model calls.

The primary endpoint is exact target-CWE detection against CWEval's
sample-level behavioral oracle. CWE-family matching is a separately reported
relaxed sensitivity analysis. SALLM and SecurityEval support target-recall
measurements but not precision because each record has only one positive label.
EvalPlus reports security-alert incidence on benign algorithmic references,
not a definitive false-positive rate.
