# VibeGuard — Project Overview

> ASE 2026 — Paris Lodron University of Salzburg
> **Authors:** Haylemicheal Mekonnen, Eslam Younis, Elbetel Reta

This document is a plain-language explanation of what the project is, why it
exists, how it is built, and what we have done so far. It is meant to be read
on its own (no code required) as a project explanation. The day-to-day
engineering checklist lives in `plan.md`.

---

## 1. What we are building (in one paragraph)

AI coding assistants make it fast to "vibe code" — generate working-looking code
with little review. That speed comes with hidden costs: weak security, code
smells, and wasteful energy/performance. **VibeGuard is two things at once:**

1. **A product** — a tool that scans Python code for security issues, code
   smells, and performance problems; measures its real runtime/energy cost in a
   sandbox; and can auto-fix some issues and compare before/after.
2. **A research instrument** — the same engine drives an empirical study that
   measures *how bad* AI-generated code actually is, compared to human code and
   to existing tools.

The product gives us a reusable analyzer; the study turns that analyzer into
evidence for a paper.

---

## 2. Why it matters

- **Security:** LLMs reproduce insecure patterns they saw in training data
  (unsafe deserialization, weak hashing, disabled TLS checks, command
  injection, etc.). These are subtle and easy to miss in review.
- **Energy/performance:** Generated code is rarely efficiency-aware; at cloud or
  edge scale, wasted CPU cycles become real cost and carbon.
- **Code quality:** Redundant logic, overly broad exception handling, and
  complexity pile up as technical debt.

We want hard numbers on these problems and a tool that can both **detect** and
(where safe) **repair** them.

---

## 3. The five research questions

The whole study is organized around five questions:

| RQ | Question | How we answer it |
|----|----------|------------------|
| **RQ1** | How prevalent are security/smell/performance issues in AI-generated code? | Scan AI-generated samples, count findings by category and source. |
| **RQ2** | Do AI solutions have more issues than human references on the *same* tasks? | Compare AI vs the human "secure reference" on matched CWEval tasks. |
| **RQ3** | Do static performance smells predict measured energy hotspots? | Run code in a sandbox, measure energy/time, correlate with perf smells. |
| **RQ4** | How often can auto-fix remove findings *without breaking behavior*? | Apply fixers, re-run the original tests, check before/after. |
| **RQ5** | How does VibeGuard compare to Bandit/Semgrep on security detection? | Run all tools on the same code, compare precision/recall in CWE space. |

---

## 4. How the system is built (architecture)

VibeGuard is split into clear layers, each with a single responsibility. This
separation is deliberate — the static scanner never executes code, and the
sandbox never owns security rules.

| Layer | Folder | Responsibility |
|-------|--------|----------------|
| **Static detection** | `security/` | Parse code, run rules → findings (security / smell / performance). Detection only. |
| **Dynamic analysis** | `sandbox/` | Execute code safely; measure CPU, memory, wall time, and energy. |
| **Auto-fix** | `fixers/` | Deterministic, rule-specific code repairs. |
| **Orchestrator** | `orchestrator/` | Tie it together: scan + measure + fix + before/after compare; exposes `/fix` and `/compare` APIs. |
| **Corpus** | `corpus/` | Turn third-party datasets into one unified study format; optionally generate AI solutions from LLMs. |
| **Experiments** | `experiments/` | Run the research questions, baselines, and statistics; emit CSV/JSON results. |

Supporting folders: `dataset/` (downloaded third-party data), `data/` (generated
corpora + caches), `results/` (study outputs), `benchmarks/` (small in-repo
smoke set), `tests/` (the test suite).

**Energy measurement** supports multiple backends, chosen automatically by
fidelity: RAPL (Linux hardware counters) → CodeCarbon → macOS `powermetrics` →
a CPU-time linear proxy that always works as a fallback.

---

## 5. The data we study

The study deliberately uses several datasets, each for a different purpose:

| Dataset | What it is | Used for |
|---------|------------|----------|
| **CWEval** | 25 security-critical Python tasks, each with a secure human reference and a pass/fail security test (oracle). | Primary corpus for RQ1, RQ2, RQ4, RQ5. |
| **EvalPlus** (HumanEval+ / MBPP+) | 542 small, pure-Python function tasks with extensive tests. | Energy study (RQ3) — small tasks give a cleaner energy signal. |
| **SALLM** | 100 security prompts paired with a known-*insecure* completion (CWE labeled). | Security-detection smoke set. |
| **SeCodePLT** | Large vulnerable/patched code pairs. | Security detection at scale. |
| **In-repo benchmark** | 11 hand-labeled samples. | Fast unit tests / sanity F1 check. |

### How a CWEval task works (the key idea)

A CWEval `*_task.py` file is a fill-in template, not just a prompt. Everything
**before** the `# BEGIN SOLUTION` marker is the prompt we send to an LLM;
everything **after** is the secure human reference (which we never show the
LLM). The matching `*_test.py` is the oracle that decides, by running pytest,
whether a solution is both *functional* and *secure*. This lets us compare AI
output against an intended-secure baseline on identical tasks.

---

## 6. The end-to-end study pipeline

```
CWEval task prompt ──(LLM generates)──> AI code sample
                                          │
                  ┌───────────────────────┼───────────────────────┐
                  ▼                        ▼                        ▼
          VibeGuard scan            sandbox measure           auto-fix
        (static findings)         (energy / time)         (compare_fix)
                  │                        │                        │
                  └──────────► run the original tests ◄────────────┘
                               (functional + security oracle)
```

In words: build a corpus from a dataset → optionally generate AI solutions from
one or more models → scan, measure, and fix each sample → check results against
the dataset's own tests → aggregate everything into per-RQ tables.

---

## 7. What we have done so far

### Foundations (done)
- The four-layer split (`security` / `sandbox` / `fixers` / `orchestrator`) with
  `/fix` and `/compare` APIs.
- Energy backends + a sandbox "measure" mode.
- A statistical harness (mean, 95% CI, Mann-Whitney U, Cliff's delta).
- A passing test suite (now **141 tests**).

### CWEval study (done — this is our main result so far)
- Loader + prompt extraction for CWEval, with CWE scoping helpers.
- Generated AI solutions from **two models** — cloud `gpt-4o-mini` and local
  `ollama:gemma4:e2b` — across all 25 Python tasks, plus the 25 human
  references.
- A pytest bridge that runs CWEval's functional + security oracles on any
  generated code.
- Baselines (Bandit, Semgrep, VibeGuard) compared in CWE-scoped space.
- A full multi-model study run producing RQ1–RQ5 CSVs (`results/study_multi/`).

### Corpus scale-up (recent work)
- **EvalPlus loader** — HumanEval+ (164) + MBPP+ (378) = **542 samples**,
  wired into the build CLI (`--datasets evalplus`). This unblocked RQ3.
- **SALLM loader** — 100 insecure-reference samples (`--datasets sallm`).
- **SeCodePLT loader** — implemented to the documented schema, but we discovered
  the *downloaded* Python splits are mislabeled (they contain C/C++ CVE data, so
  0 Python rows). The loader is correct; the dataset needs re-downloading.

### Energy study / RQ3 (recent work)
- A dedicated runner, `experiments/run_energy.py`, that measures each EvalPlus
  sample repeatedly, then compares the energy/time of samples *with* a static
  performance smell vs those *without* — using Mann-Whitney U and Cliff's delta.
- It writes per-sample stats, a correlation table, a run summary, and a
  `METHODS.md` documenting the protocol and threats to validity.

---

## 8. What we have found so far

From the multi-model CWEval run (75 samples) and the RQ3 energy smoke run:

- **AI code is often "functionally plausible but insecure."** Both models passed
  ~64% of functional tests but only ~28–36% of *security* tests. Many samples
  work yet hide vulnerabilities.
- **Cloud beat local on security.** `gpt-4o-mini` passed more security tests than
  `gemma4:e2b`, at the same functional rate.
- **Static tools under-detect these vulnerabilities.** On the CWE-scoped
  comparison, Semgrep had the best precision but all tools (including VibeGuard)
  had low recall — many CWEval CWE classes are simply outside current rule
  coverage. This is reported honestly as a limitation.
- **Auto-fix is immature for real security repair.** Repair triggered on only one
  sample, and it still failed the security oracle afterward — a negative result
  we document rather than hide.
- **Energy/perf signal is weak on the current backend.** Samples with a perf
  smell showed ~22% higher wall time (right direction) but the effect was
  negligible/non-significant, because the only available backend on macOS is a
  CPU-time proxy dominated by interpreter startup. A real signal needs Linux +
  RAPL hardware counters.

These findings are the backbone of the paper's narrative: AI code looks fine,
often isn't secure, and today's static tools (ours included) don't fully catch
it — which is exactly why dedicated tooling and honest measurement matter.

---

## 9. What is left

- **Run RQ3 on Linux with RAPL** for a publication-quality energy result (the
  runner is ready; only the platform/backend is missing).
- **Re-download SeCodePLT** to populate the at-scale security corpus.
- **Add security rules** for the most common uncovered CWEs (022, 918, 643, …)
  to raise VibeGuard's recall.
- **A one-command reproduce script** (build → merge → study → energy → plots).
- **Finish the plots and the paper's methods/threats write-up.**

---

## 10. How to run it (quick reference)

```bash
# Build the energy corpus (EvalPlus: 542 small Python tasks)
python -m corpus.build --datasets evalplus --out data/corpus/evalplus.jsonl

# RQ3 energy study
python -m experiments.run_energy \
  --corpus data/corpus/evalplus.jsonl --out-dir results/energy \
  --runs 20 --warmup 3 --energy-backend auto --max-samples 50

# Full RQ1–RQ5 study on the multi-model CWEval corpus
python -m experiments.run_study \
  --corpus data/corpus/cweval_multi.jsonl --out-dir results/study_multi --skip-energy

# Run the test suite
python -m pytest tests/
```

---

*This overview reflects the project state as of 2026-06-01. For the detailed,
task-by-task status and commands, see `plan.md`.*
