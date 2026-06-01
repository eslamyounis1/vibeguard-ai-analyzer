# VibeGuard on AI-Generated Code: An Empirical Study with CWEval

**Draft — generated from `results/study_multi/` (2026-06-01)**  
**Status:** Internal working draft; fill in author list, venue formatting, and related work before submission.

---

## Abstract

Large language models (LLMs) increasingly produce application code, but static analyzers and repair tools are still evaluated mainly on hand-written or synthetic snippets. We present an empirical study of **VibeGuard**—a layered analyzer combining security rules, code-smell and performance heuristics, sandbox measurement, and deterministic auto-fix—on **CWEval**, a benchmark of 25 Python security-oriented coding tasks with functionality and security pytest oracles. We generate solutions with **GPT-4o-mini** (cloud) and **Gemma4 2B** (local via Ollama), compare them to human secure references, and measure (RQ1) static finding prevalence, (RQ2) matched AI-vs-human differences, (RQ4) repair effectiveness, and (RQ5) detection quality against Bandit and Semgrep under CWE-scoped labels. Our results show that **64%** of AI samples pass functionality tests but only **28–36%** pass security tests; static tools achieve low recall on oracle failures (best F1 **0.40** for Semgrep on scoped CWEs); and a single auto-fix on unsafe YAML deserialization removes a static finding without restoring security-test success. We argue that security evaluation of AI code must use **outcome-based oracles**, not static counts alone, and that repair pipelines need task-specific validation beyond lint-level fixes.

---

## 1. Introduction

### 1.1 Motivation

AI coding assistants can produce plausible implementations quickly. Whether those implementations are **secure** is harder to judge from syntax or style alone. Practitioners often run Bandit, Semgrep, or custom rule packs—but the relationship between static warnings and real vulnerabilities in LLM output is under-measured.

**VibeGuard** targets this gap as an integrated pipeline: static scan → optional auto-fix → optional sandbox profiling/energy → compare before/after with behavioral checks. This paper asks how useful that pipeline is when the subject is **AI-generated** code on a security benchmark, not just the tool’s in-repo smoke set.

### 1.2 Research questions

| RQ | Question |
|----|----------|
| **RQ1** | How prevalent are security, smell, and performance findings in AI-generated vs human-reference code? |
| **RQ2** | On matched CWEval tasks, do AI solutions exhibit more static findings than secure human references? |
| **RQ3** | Do static performance smells predict measured energy hotspots? *(Not evaluated in this run—see Section 6.)* |
| **RQ4** | How often does VibeGuard auto-fix remove findings while preserving CWEval functionality and security tests? |
| **RQ5** | How does VibeGuard compare to Bandit and Semgrep on detecting CWE labels that overlap VibeGuard’s rule set, and how do static outcomes align with CWEval security tests? |

### 1.3 Contributions

1. A reproducible harness (`corpus.build`, `experiments.run_study`) connecting CWEval tasks, multi-model corpora, static baselines, pytest oracles, and repair.
2. Empirical measurements on **25 Python CWEval tasks × 2 LLMs** (50 AI samples) plus human references.
3. Evidence that **static finding density anti-correlates with oracle security** on this benchmark.
4. A negative result on repair: one applied fix does not pass CWEval security tests post-fix.

---

## 2. Background and related work

*(To be expanded by authors.)*

- **CWEval** — Security-oriented code generation benchmark; each task includes functionality and security test suites.
- **Static analysis for Python** — Bandit (security-focused), Semgrep (pattern rules), Ruff/Pylint (style/smell).
- **LLM code security** — Prior work on Copilot/ChatGPT vulnerability rates; contrast with our tool-centric + oracle-centric evaluation.

**Positioning:** Unlike pure generation benchmarks (HumanEval pass@k), we treat CWEval **security pytest** as ground truth for “secure enough for this task,” and static tools as **predictors** of that oracle.

---

## 3. VibeGuard architecture

VibeGuard separates concerns:

| Layer | Role |
|-------|------|
| `security/` | Static detection (security, smells, performance rules) |
| `fixers/` | Deterministic transforms per rule |
| `sandbox/` | Runtime measurement (energy, CPU); measure mode without profiler overhead |
| `orchestrator/` | `compare_fix`: scan → fix → re-scan → optional CWEval pytest |
| `corpus/` | Build JSONL corpora from `dataset/cweval` + LLM providers |
| `experiments/` | `run_study`, `run_baselines`, statistics helpers |

**CWEval prompt extraction:** Task files split at `# BEGIN SOLUTION`; only the prompt portion is sent to the LLM; the reference solution below the anchor is stored as `source=human`.

---

## 4. Methodology

### 4.1 Benchmark and corpus

- **Benchmark:** CWEval Python core — **25** tasks (`dataset/cweval/benchmark/core/py/`).
- **Human references:** Full task files with secure solutions (`data/corpus/cweval_ref.jsonl`, n=25).
- **AI generations:** One completion per task per model:
  - `openai:gpt-4o-mini` → `data/corpus/cweval_ai.jsonl`
  - `ollama:gemma4:e2b` → `data/corpus/cweval_gemma.jsonl`
- **Merged study corpus:** `data/corpus/cweval_multi.jsonl` — **75** samples (25 human + 25 + 25 AI).

**Generation settings:** Provider defaults in `corpus/providers/`; temperature as configured per provider; prompts from CWEval-style task headers.

### 4.2 Study execution

```bash
python -m experiments.run_study \
  --corpus data/corpus/cweval_multi.jsonl \
  --out-dir results/study_multi \
  --skip-energy
```

- **Environment:** macOS 15.5, arm64, Python 3.13.4 (see `results/study_multi/METHODS.md`).
- **RQ4/RQ5 on AI only:** Human references excluded from repair and scoped detection aggregates (`ai_only_rq4_rq5: true`).
- **CWE scoping (RQ5):** Metrics computed only for CWEs with VibeGuard rules:  
  CWE-78, 89, 95, 295, 327, 338, 489, 502, 617, 798 (**10** types). CWEval tasks use **additional** CWE classes (e.g. CWE-020, 022, 918) without VibeGuard rules—reported separately via `in_scope` in oracle tables.

### 4.3 Metrics

- **Static findings:** Counts by category (security, code_smell, performance); mean per sample (RQ1).
- **CWEval oracle:** `pytest -m functionality` and `pytest -m security` per task test file.
- **RQ5 detection:** Precision, recall, F1 vs expected CWE on in-scope samples; static TP/FP/FN vs oracle secure outcome.
- **RQ4 repair:** `changed` if auto-fix modified code; `cweval_secure_after` for post-fix security tests.

### 4.4 Threats to validity

- **Single machine / OS** — No RAPL energy in this run (`--skip-energy`).
- **Small n** — 25 tasks; wide confidence intervals; exploratory not confirmatory.
- **Two models** — Not representative of all LLMs; prompt and decoding affect results.
- **Rule coverage** — VibeGuard implements a subset of CWEval CWEs; fair tool comparison uses scoped CWE intersection.
- **Human baseline** — References are *intended* secure solutions; residual static findings reflect rule strictness, not necessarily vulnerabilities.

---

## 5. Results

### 5.1 RQ1 — Prevalence of static findings

**Table 1.** Mean static findings per sample (`results/study_multi/rq1_by_source.csv`).

| Source | n | Security | Code smell | Performance | **Total** | % samples with ≥1 finding |
|--------|---|----------|------------|-------------|-----------|---------------------------|
| Human (secure ref) | 25 | 0.04 | 0.32 | 0.00 | **0.36** | 32% |
| GPT-4o-mini | 25 | 0.08 | 0.16 | 0.00 | **0.24** | 20% |
| Gemma4 e2b | 25 | 0.04 | 0.36 | 0.04 | **0.44** | 28% |

**Finding:** AI code does not uniformly show *more* static noise than human references. GPT has the **lowest** mean total findings; Gemma the **highest**, driven by smell/performance heuristics. Security-category means remain low (0.04–0.08 per sample).

**Interpretation:** Static prevalence is a poor proxy for “more dangerous” on this set. Secure references still trigger smell rules (e.g. broad exception handlers).

---

### 5.2 RQ2 — AI vs human on matched tasks

**Table 2.** Aggregate (`rq2_ai_vs_human.csv`): human mean total **0.36**; pooled AI (both models) **0.34**.

Per-task (`rq2_matched_tasks.csv`, 25 tasks):

- **2 tasks** where mean AI findings **exceed** human: `cwe_502_0` (deserialization), `cwe_643_0` (XML; Gemma contributes 4 findings).
- **4 tasks** where mean AI findings are **below** human (e.g. `cwe_022_2`, `cwe_327_2`, `cwe_329_0`, `cwe_732_2`).
- **Majority:** matched zero or equal static totals.

**Finding:** Matched-task static comparison does not show a consistent “AI is worse” signal; differences are task-specific and tool-heuristic-specific.

---

### 5.3 RQ5 — Static tools vs CWEval oracle

#### 5.3.1 Scoped detection (50 AI samples, 10 CWE types)

**Table 3.** Tool comparison (`rq5_baselines.csv`).

| Tool | Precision | Recall | **F1** | TP | FP | FN |
|------|-----------|--------|--------|----|----|-----|
| Semgrep | 1.00 | 0.25 | **0.40** | 2 | 0 | 6 |
| Bandit | 0.17 | 0.25 | 0.20 | 2 | 10 | 6 |
| VibeGuard | 0.33 | 0.12 | 0.18 | 1 | 2 | 7 |

**Finding:** Semgrep achieves perfect precision but recalls only **25%** of in-scope positive cases. All tools miss most scoped oracle failures. Bandit trades precision for more false positives.

#### 5.3.2 Oracle pass rates (functionality vs security)

**Table 4.** CWEval pytest outcomes (`rq5_static_vs_oracle.csv`).

| Model | Functional pass | Security pass | Both pass | Functional **but not** secure |
|-------|-----------------|---------------|-----------|-------------------------------|
| GPT-4o-mini | 16/25 (64%) | 9/25 (36%) | 9/25 | **7/25 (28%)** |
| Gemma4 e2b | 16/25 (64%) | 7/25 (28%) | 6/25 | **10/25 (40%)** |

**Finding:** Equal functionality rates; GPT passes **more** security tests than local Gemma. A large fraction of “working” code remains **insecure under CWEval’s security suite**—the central empirical punchline.

#### 5.3.3 Static–oracle alignment

- Among **in-scope** samples flagged insecure by oracle (**5** instance-level failures in scoped set), only **1** had a static true positive (GPT on `cwe_502_0`, CWE-502).
- Many failures involve CWEs **outside** VibeGuard scope (CWE-020 open redirect, CWE-022 path traversal, CWE-918 SSRF, etc.)—coverage limits dominate recall.

**False comfort:** Samples with `cweval_functional=True` and `cweval_secure=False` are common; static silence does not imply security.

---

### 5.4 RQ4 — Auto-repair

**Table 5.** Repair outcomes (`rq4_repair.csv`).

| Task | Model | Changed | Findings before→after | Secure before | Secure after |
|------|-------|---------|------------------------|---------------|--------------|
| cwe_502_0 | GPT-4o-mini | **Yes** | 1 → 0 | Fail | **Fail** |

- **50** AI samples processed; **1** code change (unsafe YAML load fixer).
- Post-fix: static finding removed; CWEval **functionality and security still fail**.
- Gemma on `cwe_502_0`: finding remains (1→1); no repair applied.

**Finding:** The repair pipeline is rarely triggered and does not demonstrate security repair validated by CWEval on this run. Report as **limitation / future work**, not as a successful security fixer evaluation.

---

### 5.5 RQ3 — Energy

Not run (`rq3_energy_rows: 0`, `--skip-energy`). Defer to EvalPlus / HumanEval+ track per implementation plan.

---

## 6. Discussion

### 6.1 Static analysis undervalues and overvalues risk

- **Undervalues:** Oracle-detected vulnerabilities on out-of-scope CWEs produce **zero** VibeGuard/Bandit/Semgrep hits in scoped metrics.
- **Overvalues:** Human secure references average **0.36** findings; practitioners could waste triage effort on benchmark-acceptable reference code.

### 6.2 Implications for VibeGuard

1. **Expand rule coverage** toward high-frequency CWEval CWE gaps (020, 022, 078, 918, 643, …).
2. **Gate fixes on oracle tests** — apply fixers only when `compare_fix` runs CWEval security markers (already wired; need more rules/fixers).
3. **Present dual metrics** in product UI: static findings **and** optional test-oracle status when benchmark metadata is available.

### 6.3 Implications for AI code evaluation

Cloud GPT-4o-mini slightly outperforms local Gemma4 2B on security tests at equal functionality—useful for cost/privacy tradeoff discussion, not a universal ordering of models.

### 6.4 Limitations

See Section 4.4. Primary limitation: **n=25** tasks and **partial CWE overlap** between tool and benchmark.

---

## 7. Conclusion

We evaluated VibeGuard on CWEval with two LLMs and human secure baselines. Static finding counts **do not** track oracle security; **36–64%** of AI solutions fail security tests despite often passing functionality tests; Semgrep leads scoped F1 but with **low recall**; and auto-fix **does not** restore security-test success in our sole repair case. Future work should enlarge the corpus (SeCodePLT), add rules for missing CWEs, run energy studies (RQ3), and require oracle validation for any claimed security repair.

---

## Appendix A — Artifact map

| Artifact | Path |
|----------|------|
| Merged corpus | `data/corpus/cweval_multi.jsonl` |
| Study outputs | `results/study_multi/` |
| RQ1 table | `rq1_by_source.csv` |
| RQ2 per-task | `rq2_matched_tasks.csv` |
| RQ4 repair | `rq4_repair.csv` |
| RQ5 tools | `rq5_baselines.csv` |
| RQ5 oracle | `rq5_static_vs_oracle.csv` |
| Plots | `plots/rq1_by_source.png`, `plots/rq4_repair.png` |
| Methods snippet | `METHODS.md` |
| Implementation plan | `plan.md` |

---

## Appendix B — Suggested figures for paper

1. **Bar chart:** Table 4 (functional vs secure vs both) by model.
2. **Grouped bar:** Table 1 (finding categories by source).
3. **Sankey or confusion-style:** static alert vs oracle secure (in-scope subset).
4. **Case study:** `cwe_502_0` — AI code, static TP, fix applied, oracle still fails.

---

## Appendix C — Placeholder sections for authors

- [ ] Related work (15–20 citations)
- [ ] Tool configuration versions (Bandit, Semgrep, rule pack hashes)
- [ ] Exact LLM prompts and decoding parameters
- [ ] Statistical tests if expanding sample size
- [ ] Ethics / responsible disclosure (benchmark only, no deployed systems)

---

*Reproduce: see commands in `plan.md` § Empirical results / Immediate next tasks.*
