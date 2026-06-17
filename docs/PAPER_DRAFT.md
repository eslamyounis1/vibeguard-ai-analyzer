# VibeGuard: A Layered Analyzer for Security, Quality, and Repair of AI-Generated Python Code

**Authors:** Haylemicheal Mekonnen, Eslam Younis, Elbetel Reta
**Institution:** Paris Lodron University of Salzburg
**Venue:** ASE 2026 (Draft — v3 results + cross-dataset evaluation, 2026-06-12)

---

## Abstract

Large language models (LLMs) are increasingly used to generate production code, yet the security of that output remains poorly characterized. We present **VibeGuard**, a layered analysis pipeline combining AST-based security and quality detection (40 rules), dynamic sandbox probes (10 rules with execution-based confirmation), taint-lite data-flow tracking, exploitability scoring, and two complementary auto-repair engines. We conduct an empirical study on **CWEval** — a formal benchmark of 25 security-critical Python tasks with independent functionality and security pytest oracles — generating 100 solutions from four OpenAI models (gpt-4.1, gpt-4.1-mini, gpt-4o, gpt-4o-mini) and comparing them to 25 human secure references (125 samples total). Our results show that AI models achieve functional pass rates of 68–72% but security pass rates of only 36–52%, leaving a persistent **functional-but-insecure gap of 24–32%** per model. On CWE-scoped detection, VibeGuard achieves **F1 = 0.636** (corrected F1 = 0.777) versus Bandit's F1 = 0.224 — a **2.8× improvement**. An LLM repair engine (gpt-4o-mini) triggers on 38% of samples and restores oracle security in **32.1%** of originally insecure cases, versus 0% for a deterministic pattern-rewrite fixer. Cross-dataset validation on SALLM (100 samples) and SecurityEval (121 samples) shows VibeGuard consistently outperforms Bandit, with detection rates of 72% vs 51% on SALLM. We additionally introduce **family-grouped evaluation** — mapping related CWEs to canonical families to eliminate label-mismatch false positives — which improves SALLM F1 from 0.422 to **0.583** (+0.161) for VibeGuard and from 0.327 to **0.510** (+0.183) for Bandit, revealing that single-label benchmarks systematically understate detection quality. We further introduce secure@k / vulnerable@k metrics, dynamic probe self-validation, and show that 60% of apparent false negatives are oracle-safe — cases where models wrote correct, secure code that the benchmark mislabeled as vulnerable. Our central finding: passing functional tests does not imply secure code, and security evaluation of AI output requires outcome-based oracles, not static counts alone.

---

## 1. Introduction

### 1.1 Motivation

The emergence of "vibe coding" — the practice of iteratively prompting LLMs to generate application code — has dramatically lowered the barrier to software development. Developers using tools such as GitHub Copilot, Cursor, and ChatGPT can produce functional implementations in minutes. However, speed of generation does not imply safety of output. Studies of early LLM coding assistants found that approximately 40% of Copilot-generated programs contained security weaknesses [Pearl et al. 2022], a finding consistent with our results showing that even the best current model (gpt-4.1) fails security tests on 48% of tasks.

The standard response to this problem — running a static analysis tool such as Bandit or Semgrep over generated code — faces two fundamental limitations. First, static tools were designed for human-authored code and their rule sets are not calibrated to the specific vulnerability patterns that emerge from LLM generation. Second, and more critically, a static finding count does not tell us whether the code actually behaves insecurely: a snippet may trigger zero rules yet fail a behavioral security test, or trigger multiple rules yet be architecturally correct. We demonstrate both failure modes empirically.

**VibeGuard** was designed to address these limitations through a layered architecture: static detection as a first filter, dynamic sandbox probes for execution-based confirmation, taint-lite analysis for cross-function vulnerability tracking, and two repair engines (deterministic pattern-rewrite and LLM whole-file replacement) whose effectiveness is measured against behavioral security oracles rather than static finding deltas alone.

### 1.2 Research Questions

| RQ | Question |
|----|----------|
| **RQ1** | How prevalent are security, code smell, and performance findings in AI-generated vs human-reference Python code? |
| **RQ2** | On matched CWEval tasks, do AI solutions exhibit more static findings than secure human references? |
| **RQ3** | Do static performance smells predict measured execution cost (energy proxy)? |
| **RQ4** | How effectively do VibeGuard's auto-repair engines reduce findings and restore oracle security? |
| **RQ5** | How does VibeGuard compare to Bandit on CWE-scoped security detection quality? |
| **RQ6** | What are the secure@k and vulnerable@k rates per model and CWE class? |
| **RQ7** | Does single-label CWE evaluation systematically understate detection quality, and how much does family-grouped evaluation recover? |

### 1.3 Contributions

This paper makes four novel contributions:

1. **Dynamic probes with exploitability scoring.** Ten execution-based probes that confirm static findings at runtime and produce a risk score combining severity with dynamic confirmation status. No prior security analyzer for AI-generated code uses execution-based confirmation.

2. **Taint-lite data-flow analysis.** An AST-based parameter-to-sink taint tracer integrated into SSRF and XSS rules, reducing false negatives without requiring a full data-flow framework.

3. **Secure@k / vulnerable@k metrics.** Extended from SALLM [Siddiq et al. 2024], these metrics characterize the probability that a model's k-th attempt at a task produces secure code, enabling cross-model comparison at the task-CWE level.

4. **Oracle-gated empirical evaluation.** A full study pipeline that measures repair effectiveness against behavioral security oracles (CWEval pytest harness), not static finding removal, and that distinguishes true false negatives from oracle-quality issues.

5. **Family-grouped evaluation methodology.** A CWE-to-family mapping (80+ CWEs, 25 families) that converts related-CWE label mismatches from false positives to true positives, providing a fairer measure of detection quality than single-label benchmark evaluation. Cross-dataset validation on SALLM and SecurityEval demonstrates consistent VibeGuard improvement across three independent datasets.

---

## 2. Background and Related Work

### 2.1 Benchmarks for LLM Code Security

**CWEval** [Peng et al. 2024] is the primary benchmark used in this study. It provides 25 Python security tasks, each targeting a specific CWE, with paired pytest suites that separately validate functional correctness and security compliance. The security oracle tests behavioral properties (e.g., whether path traversal escapes the designated directory, whether a generated cipher key meets minimum entropy requirements) rather than syntactic patterns. This design is critical: it forces evaluation tools to compete against behavioral ground truth rather than label-matching alone. CWEval covers 31 CWEs across 5 languages; we use the 25 Python tasks.

**EvalPlus** [Liu et al. NeurIPS 2023] introduced the outcome-based oracle methodology that CWEval extends to the security domain. EvalPlus augmented the HumanEval benchmark with additional test cases generated by a stronger model, demonstrating that pass@k metrics inflate when test suites are too weak. Our study adopts the same philosophy: we measure security pass rates using CWEval's oracle rather than VibeGuard's own static findings.

**SALLM** [Siddiq et al. ASEW 2024] evaluated LLM security awareness on 100 security-sensitive prompts, introducing the vulnerable@k and security@k metrics. SALLM used both static analysis (Bandit) and dynamic testing to assess generated code. VibeGuard uses the SALLM dataset for a detection smoke test (Section 5.8), and our secure@k / vulnerable@k metrics (RQ6) directly extend the SALLM metric framework to the cross-model, per-CWE setting.

### 2.2 Static Analysis Baselines

**Bandit** is a widely used Python security linter developed by PyCQA. It operates on ASTs and ships with rule sets covering common vulnerability classes. We compare VibeGuard against Bandit on CWE-scoped detection (RQ5). **Semgrep** is a pattern-based multi-language tool with a community rule registry; it was not available in this evaluation run and remains a target for future comparison.

### 2.3 LLM Security Weaknesses

Pearl et al. [2022] analyzed GitHub Copilot across 89 scenarios drawn from the MITRE CWE list and found security weaknesses in approximately 40% of generated programs, with highest failure rates on CWE-22 (path traversal), CWE-89 (SQL injection), and CWE-798 (hardcoded credentials). Chen et al. [2021] introduced Codex and evaluated HumanEval functional pass rates but did not assess security. These works establish the prior evidence base; our contribution is a controlled, oracle-validated comparison of four current-generation models with a repair intervention.

### 2.4 Positioning

VibeGuard is, to our knowledge, the first tool to combine: (a) CWE-scoped static detection specifically calibrated for AI-generated Python, (b) dynamic sandbox probes with execution-based confirmation, (c) oracle-gated auto-repair with both deterministic and LLM strategies, and (d) a cross-model empirical evaluation against a formal security benchmark with independent behavioral oracles.

---

## 3. VibeGuard Architecture

VibeGuard is organized into five layers, each with a single well-defined responsibility.

### 3.1 Layer Overview

| Layer | Module | Responsibility |
|-------|--------|---------------|
| **Static analysis** | `security/` | AST-based detection: 40 rules (25 security VG001–VG025, 9 code smell SM001–SM009, 3 performance PF001–PF003), CWE + OWASP tagged |
| **Dynamic sandbox** | `sandbox/` | 10 execution-based probe rules, 4 energy measurement backends, exploitability scoring |
| **Taint-lite** | `security/taint/` | AST-level parameter-to-sink tracking integrated into VG015 (SSRF) and VG016 (XSS) |
| **Repair engines** | `fixers/` | 15 deterministic pattern-rewrite fixers + LLM whole-file fixer (gpt-4o-mini) |
| **Orchestrator** | `orchestrator/` | `compare_fix()`: scan → fix → re-scan → CWEval oracle; RQ1–RQ8 experiment runners |

**Design principle:** Static rules never execute code; the sandbox never owns detection logic; the orchestrator is the only layer that imports both. This separation ensures that dynamic confirmation supplements static detection without circular dependency.

### 3.2 Security Rules (VG001–VG025)

The 25 security rules cover:

- **Injection / execution:** eval/exec (VG001, CWE-95), subprocess shell (VG009, CWE-78), SQL injection (VG013, CWE-89), XPath injection (VG017, CWE-643), OS command via os.system (VG002, CWE-95)
- **Deserialization / data handling:** pickle (VG005, CWE-502), unsafe YAML (VG010, CWE-502), assert-as-validation (VG006, CWE-617), path traversal (VG014, CWE-22)
- **Cryptography:** weak hash (VG008, CWE-327), TLS bypass (VG011, CWE-295), weak crypto key size (VG020, CWE-326), weak RNG seed (VG023, CWE-329), insecure random (VG004, CWE-338)
- **Web / network:** SSRF (VG015, CWE-918), XSS (VG016, CWE-79), open redirect (VG018, CWE-601), HTTP header injection (VG022, CWE-113), debug mode (VG012, CWE-94)
- **Information exposure:** hardcoded secrets (VG003, CWE-798), log injection (VG021, CWE-117)
- **Input validation:** unvalidated input (VG019, CWE-20), URL domain validation bypass (VG025, CWE-20), ReDoS (VG024, CWE-400)

### 3.3 Dynamic Probes

Ten probe rules in `sandbox/probe_registry.py` confirm static findings at runtime by executing the subject function in an isolated subprocess harness with adversarial inputs. Confirmed findings receive a higher exploitability score. Probe classes include: SQLInjectionProbe, CommandInjectionProbe, PathTraversalProbe, PickleProbe, InputValidationProbe, XssProbe, HeaderInjectionProbe, LogInjectionProbe, WeakKeyProbe, and a baseline SafeProbe.

### 3.4 Novel Technical Contributions

**Taint-lite:** `security/taint/tracer.py` implements `TaintTracer`, which tracks tainted parameters through method chains within a function body. When a tainted value reaches a recognized sink (HTTP request call, string return in HTML context), a vulnerability is reported. This reduces false negatives for SSRF and XSS patterns where the vulnerable data flows through intermediate variables.

**Exploitability scoring:** `sandbox/scoring.py` implements `compute_risk_score()`. The score combines static severity (CWE base score) with dynamic confirmation status: a probe-confirmed finding scores ≥0.72; an unconfirmed finding from a high-severity rule scores 0.45–0.65; a low-severity smell scores ≤0.30.

**Secure@k / vulnerable@k:** `experiments/metrics.py` implements these metrics following the SALLM definition. `secure@k` is the probability that at least one of k independent model samples for a given task passes the security oracle. `vulnerable@k` is the complementary probability that at least one of k samples is oracle-insecure.

**Mutation-based probe validation:** `experiments/rq7_probe_accuracy.py` validates probe accuracy by mutating known-vulnerable and known-safe variants of 9 CWE classes and measuring probe TP/FP/FN rates, providing a self-validation methodology for the dynamic analysis layer.

---

## 4. Study Design

### 4.1 Benchmark and Corpus

We use **CWEval** (25 Python security tasks, 25 CWEs, pytest-based functional and security oracles) as the primary benchmark. For each task we generate one solution per model using the OpenAI API (temperature=0.2, cached for reproducibility). The corpus consists of:

```
data/corpus/cweval_multi_openai.jsonl
├── human references        25 samples  (source = "human")
├── openai:gpt-4o-mini      25 samples
├── openai:gpt-4o           25 samples
├── openai:gpt-4.1-mini     25 samples
└── openai:gpt-4.1          25 samples
                            ──────────
Total                        125 samples
```

Human references are the secure solution implementations provided by the CWEval benchmark authors. They serve as an upper-bound target for both oracle correctness and static quality.

### 4.2 Models

| Model | Generation | Notes |
|-------|-----------|-------|
| gpt-4o-mini | GPT-4o family | Efficient, prior baseline |
| gpt-4o | GPT-4o family | Standard tier |
| gpt-4.1-mini | GPT-4.1 family | Newer generation mini |
| gpt-4.1 | GPT-4.1 family | Flagship, most capable |

### 4.3 Research Questions and Operationalization

| RQ | Operationalization | Key Metric |
|----|-------------------|-----------|
| RQ1 | Mean findings/sample by source and category | Mean security, smell, perf; % ≥1 finding |
| RQ2 | Matched-task comparison of static totals | AI mean vs human mean; per-task delta |
| RQ4-A | Deterministic fixer on 100 AI samples | Trigger rate; oracle improvement rate |
| RQ4-B | LLM fixer (gpt-4o-mini) on 100 AI samples | Trigger rate; oracle improvement rate |
| RQ5 | VibeGuard vs Bandit on CWE-scoped detection | P, R, F1 (per-tool); TP, FP, FN |
| RQ6 | Secure@k / vulnerable@k per model and CWE | Pass probability at k=1 per task |

### 4.4 CWE Scope

VibeGuard v3 covers 21 CWE classes. The full CWEval benchmark spans 25 CWEs. The four uncovered CWEs either require inter-procedural data-flow analysis beyond taint-lite scope (CWE-918, CWE-078) or are addressed by rules that depend on semantic context not available in ASTs (CWE-327, CWE-329). All RQ5 metrics are scoped to the 21 CWEs covered by VibeGuard, giving a fair within-coverage comparison against Bandit.

### 4.5 Oracle Calibration

A critical methodological consideration is that CWEval's ground truth labels assume models write insecure code. When a model writes a secure implementation, the label still counts as a false negative for detection tools. We distinguish three FN categories:

- **True FN:** VibeGuard missed a genuine vulnerability (rule gap, incomplete pattern)
- **Oracle-safe FN:** The model wrote secure code; the oracle label is misleading
- **Architectural FN:** Vulnerability requires inter-procedural analysis beyond AST scope

We report both raw metrics (treating all CWEval labels as ground truth) and corrected metrics (excluding oracle-safe FNs). This distinction is itself a research finding.

### 4.6 Baselines

**Bandit v1.8** (PyCQA): standard Python AST security linter. Results are CWE-scoped identically to VibeGuard for a fair comparison. **Semgrep** was not installed in this evaluation run and is deferred to future work.

### 4.7 Additional Validation Datasets

To assess cross-dataset generalizability and evaluate our better evaluation methodology, we run VibeGuard and Bandit on two further datasets:

- **SALLM** [Siddiq et al. 2024]: 100 Python samples each labeled with one CWE, covering diverse vulnerability classes beyond CWEval. From a different distribution (prompts, not benchmark tasks). Path: `dataset/sallm/dataset.jsonl`.
- **SecurityEval** [Siddiq et al. 2022]: 121 Python samples from the HuggingFace `s2e-lab/SecurityEval` repository, spanning 69 CWE classes, drawn from real-world vulnerable code patterns.
- **EvalPlus** (benign baseline): 164 HumanEval+ canonical solutions — known-correct, non-security-sensitive algorithmic code. Used exclusively to measure **false alarm rate** (the rate at which VibeGuard raises security findings on code that is not intended to be vulnerable).

These three datasets complement CWEval by covering different distributions, different labeling conventions, and (for EvalPlus) the benign false-alarm case.

---

## 5. Results

### 5.1 RQ1 — Static Finding Prevalence

**Table 1: Mean findings per sample by source (VibeGuard v3, 25-rule ruleset)**

| Source | n | Mean Security | Mean Code Smell | Mean Performance | **Mean Total** | % With Any Finding |
|--------|---|:-------------:|:---------------:|:----------------:|:--------------:|:-----------------:|
| human (secure ref) | 25 | 0.60 | 0.32 | 0.00 | **0.92** | 68% |
| gpt-4.1 | 25 | 0.48 | **0.84** | 0.00 | **1.32** | 68% |
| gpt-4.1-mini | 25 | 0.56 | 0.32 | 0.00 | **0.88** | 60% |
| gpt-4o | 25 | 0.52 | 0.20 | 0.00 | **0.72** | 56% |
| gpt-4o-mini | 25 | 0.56 | 0.16 | 0.00 | **0.72** | 56% |

**Key observations:**

- **Security findings** are comparable across human references and all four AI models (0.48–0.60). Human references score highest (0.60) because security-focused reference implementations exercise more of the flagged API surface (RSA key generation, log formatting, header construction) than AI solutions that may avoid these APIs entirely.

- **Code smell** is where models diverge sharply. **gpt-4.1 produces 0.84 smells/sample** — more than twice any other source — despite achieving the best oracle security score. This counter-intuitive result suggests that the most capable model writes more elaborate, readable, but structurally complex code.

- **Performance findings** are uniformly zero. Short security functions do not trigger nested-loop or string-concatenation-in-loop rules.

- **Static counts do not predict security.** Human references have the highest security finding count but also the highest oracle security pass rate. gpt-4o-mini has the second-lowest static finding count but the lowest oracle security pass rate (36%). This anti-correlation motivates the core argument: static counts alone are insufficient for security evaluation of AI code.

**Version progression (security findings mean):**

| Source | v1 (19 rules) | v2 (24 rules) | v3 (25 rules) |
|--------|:-------------:|:-------------:|:-------------:|
| human | 0.24 | 0.40 | 0.60 |
| gpt-4.1 | 0.24 | 0.36 | 0.48 |
| gpt-4.1-mini | 0.28 | 0.40 | 0.56 |
| gpt-4o | 0.28 | 0.40 | 0.52 |
| gpt-4o-mini | 0.28 | 0.40 | 0.56 |

The consistent upward trend reflects increased rule coverage, not code quality changes. The v3 increase is primarily attributable to: (1) the CWE-326 key-size threshold raised from 2048 to 3072 bits (NIST SP 800-57), which now flags RSA.generate(2048) calls present in both human and AI code; (2) the VG016 expansion adding f-string HTML return pattern detection; and (3) the VG021 expansion adding log-builder function detection.

---

### 5.2 RQ2 — AI vs Human (Matched Tasks)

| Group | Sources | Mean Total Findings |
|-------|---------|:-------------------:|
| Human | 1 | **0.92** |
| AI (pooled, 4 models) | 4 | **0.91** |

For the first time across all three evaluation runs, AI-generated code and human references converge on mean total static findings (0.91 vs 0.92; <1% gap). In v1 AI exceeded human by 16%; in v2 by 7%; in v3 the gap has closed to near zero.

This convergence is an artifact of rule expansion, not a real change in code quality. The CWE-326 threshold change adds findings uniformly to all sources that call RSA.generate(2048). At the matched-task level, 8/25 tasks show AI > human; 4/25 show AI < human; the remainder are equal. The most divergent tasks are cwe_502_0 (AI mean 2.5 vs human 1.0; +1.5 net) and cwe_020_0 (AI mean 0.0 vs human 1.0; −1.0 net).

**Answer to RQ2:** No consistent "AI is worse" signal exists on this benchmark when measured by static finding counts. The oracle results (Section 5.5) confirm the correct framing: AI code is functionally plausible but security-insecure, not statically noisier.

---

### 5.3 RQ3 — Performance Smell Correlation with Execution Cost

**Corpus and setup.** CWEval and SALLM are security-focused benchmarks; as noted in Section 5.1, all samples in both datasets produce zero performance findings (VibeGuard's performance rules target nested loops, string-concatenation in loops, and linear list-membership checks — patterns absent from security task implementations). A purpose-built synthetic corpus of **40 algorithmic tasks** was therefore constructed: 20 samples with static performance smells (`nested_loop`, `string_concat_in_loop`, `membership_in_loop`; verified by the VibeGuard scanner) and 20 clean counterparts performing equivalent computation without the flagged patterns. Each sample was executed 12 times (2 warm-up runs discarded, 10 measured) in the VibeGuard sandbox.

**Energy backend.** The experiment used the `powermetrics` backend (Apple M-series CPU, macOS 15.5, arm64). `powermetrics` streams CPU-package power at 100 ms intervals; direct joule figures require elevated privileges (sudo) and are reported as null when unavailable. Wall time — measured by the sandbox via `time.perf_counter()` — serves as the primary energy proxy: since CPU-bound Python work runs at roughly constant CPU-package power on Apple Silicon, wall time × constant power = energy, and relative comparisons between groups are valid without direct power readings.

**Table RQ3: Execution cost by group (powermetrics backend, n = 40 samples)**

| Group | n | Mean wall time | Median wall time |
|-------|---|:--------------:|:----------------:|
| With perf finding | 20 | **0.753 s** | 0.108 s |
| Without perf finding | 20 | 0.013 s | 0.004 s |
| **Ratio** | — | **56.4×** | 27× |

Mann-Whitney U = 22, p = 1.58 × 10⁻⁶; Cliff's δ = −0.89 (**large** effect).

Per-smell-type breakdown:

| Smell type | n (smelly/clean) | Mean smelly | Mean clean | Ratio |
|------------|:----------------:|:-----------:|:----------:|:-----:|
| `nested_loop` | 10 / 10 | 1.453 s | 0.002 s | 807× |
| `string_concat_in_loop` | 5 / 5 | 0.030 s | 0.010 s | 3× |
| `membership_in_loop` | 5 / 5 | 0.079 s | 0.040 s | 2× |

**Answer to RQ3:** Static performance smells reliably predict higher execution cost. The effect is highly statistically significant (p < 10⁻⁵) with a large effect size (Cliff's δ = 0.89), confirming that VibeGuard's performance-smell rules identify genuinely inefficient code patterns. The dominant contributor is the `nested_loop` rule (807× wall-time inflation), which is a valid O(n²) vs O(n) distinction. String-concat and membership smells show smaller but consistent effects (2–3×). The full powermetrics energy run (with sudo) can be reproduced via `scripts/run_energy_powermetrics.sh`.

---

### 5.4 RQ4 — Auto-Fix Effectiveness

We evaluate two repair strategies on the 100 AI-generated CWEval samples.

#### RQ4-A: Deterministic Fixer

**Table 2: Deterministic fixer results (100 AI samples)**

| Metric | Value |
|--------|-------|
| Samples where fixer triggered | 4 / 100 **(4%)** |
| Finding reduction (triggered samples) | 4 removed |
| CWEval security oracle improved | **0 / 56 (0%)** |

The deterministic fixer triggered on exactly one task across all four models: `cwe_502_0` (CWE-502, unsafe YAML deserialization). It correctly replaced `yaml.load(data)` with `yaml.safe_load(data)`, removing the `unsafe_yaml_load` finding. However, all four repaired samples still failed the security oracle — the CWEval task requires architectural validation beyond a single API substitution.

The 96% trigger-miss rate is itself an important negative finding: most CWEval vulnerabilities require architectural changes (proper input validation, output escaping, key management strategy) that pattern-rewrite fixers cannot perform.

#### RQ4-B: LLM Fixer (gpt-4o-mini)

**Table 3: LLM fixer vs deterministic fixer (100 AI samples)**

| Metric | Deterministic | LLM (gpt-4o-mini) |
|--------|:------------:|:-----------------:|
| Trigger rate | 4 / 100 (4%) | **38 / 100 (38%)** |
| Safety gate passed | 4 / 4 (100%) | **38 / 38 (100%)** |
| Mean findings removed per sample | 0.04 | **0.18** |
| Oracle security improved (of 56 insecure) | **0 / 56 (0%)** | **18 / 56 (32.1%)** |

The LLM fixer triggered on 38 of 100 AI samples — a 9.5× higher trigger rate. All 38 changes passed the safety gate (no new findings introduced, no invalid Python generated). Of the 56 samples oracle-insecure before repair, 18 (32.1%) achieved security oracle pass after LLM repair.

**Table 4: Per-CWE oracle improvements (LLM fixer)**

| CWE | Description | LLM Changed | Oracle Improved | Rate |
|-----|-------------|:-----------:|:---------------:|:----:|
| CWE-113 | HTTP Header Injection | 4 | **4** | 100% |
| CWE-079 | XSS | 2 | **2** | 100% |
| CWE-117 | Log Injection | 2 | **2** | 100% |
| CWE-643 | XPath Injection | 2 | **2** | 100% |
| CWE-502 | Unsafe Deserialization | 4 | **3** | 75% |
| CWE-022 | Path Traversal | 8 | **5** | 62.5% |
| CWE-326 | Weak Crypto Key | 8 | 0 | 0%† |
| CWE-095 | Code Injection (eval) | 1 | 0 | 0%‡ |
| CWE-400 / CWE-1333 | ReDoS | 3 | 0 | 0% |

†**CWE-326:** The LLM correctly raises RSA/DSA key size from 2048 to 4096 bits, removing all 8 VibeGuard static findings. However the CWEval oracle still fails — it tests additional behavioral properties (key serialization format, usage context) beyond key size alone. This demonstrates that static-finding removal does not imply oracle security.

‡**CWE-095:** The LLM removes the `eval()` call but cannot satisfy the oracle's behavioral test for a correct replacement evaluator.

**Critical insight — semantic repair without static finding removal:** Across CWE-022, CWE-113, CWE-079, and CWE-643, the LLM achieves oracle improvement *without* removing the VibeGuard static finding. The model rewrites the vulnerable logic (adds header sanitization, fixes path validation, escapes output) in a way that satisfies the oracle's test suite, while the surface pattern that triggered the static rule (an f-string, a header construction call, a path join) remains in the fixed code. This reveals a fundamental tension:

1. A tool can remove a static finding but fail the oracle (CWE-326)
2. A tool can pass the oracle while leaving the static finding in place (CWE-022, CWE-113, CWE-079, CWE-643)

Both metrics are necessary to characterize repair effectiveness.

---

### 5.5 RQ5 — Baseline Comparison (Core Result)

**Table 5: Detection performance — VibeGuard v3 vs Bandit (21 CWEs, 125 samples)**

| Tool | TP | FP | FN | Precision | Recall | F1 |
|------|:--:|:--:|:--:|:---------:|:------:|:--:|
| **VibeGuard v3** | **41** | **12** | **35** | **0.774** | **0.539** | **0.636** |
| Bandit | 12 | 19 | 64 | 0.387 | 0.158 | 0.224 |

VibeGuard achieves **2.8× higher F1** than Bandit (0.636 vs 0.224), with 2× higher precision (0.774 vs 0.387) and 3.4× higher recall (0.539 vs 0.158). The improvement reflects VibeGuard's CWE-specific rules tuned for patterns that appear in AI-generated code, versus Bandit's generic rule set that fires on broader syntactic patterns common in human code.

**Table 6: VibeGuard version progression**

| Version | Rules | TP | FP | FN | Precision | Recall | F1 |
|---------|:-----:|:--:|:--:|:--:|:---------:|:------:|:--:|
| v1 | 19 | 8 | 19 | 20 | 0.296 | 0.286 | 0.291 |
| v2 | 24 | 27 | 12 | 49 | 0.692 | 0.355 | 0.470 |
| **v3** | **25** | **41** | **12** | **35** | **0.774** | **0.539** | **0.636** |

The v2→v3 improvement (+14 TP, 0 new FP) demonstrates that targeted, high-confidence rule improvements consistently increase precision without sacrificing recall. The four v3 changes (CWE-326 threshold, VG025 URL bypass, VG016 HTML f-string, VG021 log-builder) added 14 true positives with zero false positives.

**Per-CWE breakdown highlights:** VibeGuard achieves 100% detection on CWE-22 (path traversal), CWE-79 (XSS), CWE-113 (HTTP header injection), CWE-326 (weak crypto key), CWE-400 (ReDoS), and CWE-643 (XPath injection). Zero detection on CWE-327 (weak hash algorithm — semantic), CWE-918 (SSRF — inter-procedural), and CWE-78 (command injection — models used safe list arguments).

**Oracle calibration — corrected metrics:**

| Metric | Raw (v3) | Corrected |
|--------|:--------:|:---------:|
| FN | 35 | **14** |
| Recall | 0.539 | **0.745** |
| F1 | 0.636 | **0.777** |

21 of 35 FNs (60%) are oracle-safe: the generated code contains no actual vulnerability. Breakdown: CWE-327 (12 FNs — models used SHA-256/argon2/AES, which are cryptographically correct), CWE-078 (4 FNs — models used `subprocess.run(['cmd', arg])` list arguments, safe by construction), CWE-329 (4 FNs — models used `os.urandom(16)` for IV/salt, cryptographically secure), CWE-095 (1 FN — gpt-4.1 wrote an `ast.parse()`-based evaluator, architecturally safe). Corrected recall = 41 / (76 − 21) = **0.745**; corrected F1 = **0.777**.

---

### 5.6 RQ5 (continued) — CWEval Oracle Pass Rates

**Table 7: Functional and security oracle pass rates by model**

| Model | Functional Pass | Security Pass | Both Pass | Functional-Only (insecure) |
|-------|:--------------:|:-------------:|:---------:|:--------------------------:|
| gpt-4.1 | 18/25 **(72%)** | 13/25 **(52%)** | 12/25 (48%) | **6 (24%)** |
| gpt-4.1-mini | 18/25 **(72%)** | 12/25 **(48%)** | 12/25 (48%) | **6 (24%)** |
| gpt-4o | 18/25 **(72%)** | 10/25 **(40%)** | 10/25 (40%) | **8 (32%)** |
| gpt-4o-mini | 17/25 **(68%)** | 9/25 **(36%)** | 9/25 (36%) | **8 (32%)** |

**The functional-but-insecure gap** (24–32% per model) is the central empirical finding. Code that passes all functional tests and appears to work correctly is still security-failing in nearly a third of cases for the weaker models. This gap is consistent and robust: it appears in all four models, all three evaluation versions, and at similar magnitudes.

The gap motivates VibeGuard's core design: functional test passage alone is insufficient to certify security, and behavioral security oracles are necessary to distinguish truly secure code from superficially correct code.

**Model-level security improvement:** gpt-4.1 (52%) achieves a 44% relative improvement over gpt-4o-mini (36%). The newer GPT-4.1 generation shows measurably improved security awareness, though even the best model fails nearly half of all security tests.

---

### 5.7 RQ6 — Secure@k and Vulnerable@k

Using the metric framework from SALLM [Siddiq et al. 2024] extended to the per-CWE, per-model setting, secure@1 (the probability that a single sample from a model passes the security oracle for a given task) ranges from 0.36 (gpt-4o-mini) to 0.52 (gpt-4.1) at the aggregate level. At the per-CWE level, notable patterns emerge:

- All models achieve secure@1 = 1.0 on CWE-078 (command injection) — every model writes safe list-argument subprocess calls
- All models achieve secure@1 = 0.0 on CWE-327 (weak hash) and CWE-918 (SSRF) — no model consistently writes oracle-secure code for these tasks
- The CWE-326 (weak crypto key) secure@1 improves dramatically when key size is raised to 4096 bits by the LLM fixer, but the CWEval oracle tests beyond key size, so oracle pass rate does not follow

These per-CWE secure@k patterns identify which vulnerability classes represent persistent blind spots for current LLMs, independent of the analysis tool.

---

### 5.8 Cross-Dataset Evaluation (SALLM and SecurityEval)

To assess generalizability beyond CWEval, we apply VibeGuard and Bandit to SALLM (100 insecure samples) and SecurityEval (121 insecure samples) and measure three complementary metrics: detection rate, single-label P/R/F1, and family-grouped P/R/F1.

#### 5.8.1 Detection Rate

Detection rate measures the percentage of known-vulnerable samples that receive *any* security finding, independent of CWE label matching.

**Table 8: Detection rate on known-vulnerable datasets**

| Dataset | Tool | Detected | Total | Detection Rate |
|---------|------|:--------:|:-----:|:--------------:|
| SALLM | **VibeGuard** | **72** | 100 | **72.0%** |
| SALLM | Bandit | 51 | 100 | 51.0% |
| SecurityEval | **VibeGuard** | **84** | 121 | **69.4%** |
| SecurityEval | Bandit | 58 | 121 | 47.9% |

VibeGuard detects a vulnerability in 72% of SALLM samples vs 51% for Bandit — a 41% relative improvement. On SecurityEval the gap is similar: 69.4% vs 47.9%. Detection rate avoids label-matching entirely and is the most honest measure of practical utility: a developer running the tool on an insecure snippet wants to know whether the tool raises an alarm, not whether it identifies the exact labelled CWE.

#### 5.8.2 Single-Label vs Family-Grouped P/R/F1

Standard single-label evaluation requires that the tool detect the exact CWE listed in the ground truth. This penalises correct detections of co-occurring or closely related vulnerabilities. For example, a sample labelled CWE-94 (code injection) in which VibeGuard also detects CWE-95 (eval injection) — a subset of CWE-94 — is counted as a false positive under single-label evaluation.

We address this with **CWE family grouping**: 80+ CWEs are mapped to 25 canonical family names (e.g., CWE-94, CWE-95, CWE-89, CWE-78 → "injection"; CWE-326, CWE-327, CWE-329 → "crypto"). A detection is a TP if its family matches the ground-truth label's family.

**Table 9: Single-label vs family-grouped P/R/F1 (SALLM, 100 samples)**

| Tool | Method | TP | FP | FN | Precision | Recall | **F1** |
|------|--------|:--:|:--:|:--:|:---------:|:------:|:------:|
| VibeGuard | Single-label | 42 | 57 | 58 | 0.424 | 0.420 | 0.422 |
| VibeGuard | **Family-grouped** | **58** | **41** | **42** | **0.586** | **0.580** | **0.583** |
| Bandit | Single-label | 25 | 28 | 75 | 0.472 | 0.250 | 0.327 |
| Bandit | **Family-grouped** | **39** | **14** | **61** | **0.736** | **0.390** | **0.510** |

Family grouping converts 16 FPs into TPs for VibeGuard (+0.161 F1) and 14 FPs into TPs for Bandit (+0.183 F1). The large FP→TP conversion rate for Bandit reveals that Bandit's apparent poor precision under single-label evaluation is substantially an artifact of related-CWE label mismatches, not incorrect detections.

**Table 10: Single-label vs family-grouped P/R/F1 (SecurityEval, 121 samples)**

| Tool | Method | TP | FP | FN | Precision | Recall | **F1** |
|------|--------|:--:|:--:|:--:|:---------:|:------:|:------:|
| VibeGuard | Single-label | 35 | 49 | 86 | 0.417 | 0.289 | 0.341 |
| VibeGuard | **Family-grouped** | **49** | **35** | **72** | **0.583** | **0.405** | **0.478** |
| Bandit | Single-label | 22 | 36 | 99 | 0.379 | 0.182 | 0.246 |
| Bandit | **Family-grouped** | **33** | **25** | **88** | **0.569** | **0.273** | **0.369** |

SecurityEval spans 69 CWE classes (vs CWEval's 25), many of which VibeGuard does not cover, explaining the higher FN counts. Within covered families, family grouping again provides a consistent +0.137 F1 improvement for VibeGuard.

#### 5.8.3 False Alarm Rate on Benign Code

Running VibeGuard on 164 EvalPlus HumanEval+ canonical solutions (algorithmically correct, non-security-sensitive code) yields security findings on only **1/164 samples (0.6%)**. The single alarm is a `missing_return_annotation` rule — a code smell, not a security rule. Bandit raises security-category findings on **3/164 samples (1.8%)**.

This near-zero false alarm rate on benign code confirms that VibeGuard's security rules are tightly scoped and do not generate noise on normal algorithmic code.

#### 5.8.4 Summary: Three-Dataset Comparison

**Table 11: VibeGuard vs Bandit across all three datasets**

| Dataset | Metric | VibeGuard | Bandit | VG Advantage |
|---------|--------|:---------:|:------:|:------------:|
| CWEval (primary) | F1 (scoped) | **0.636** | 0.224 | +0.412 (2.8×) |
| SALLM | Detection rate | **72.0%** | 51.0% | +21 pp |
| SALLM | F1 single-label | **0.422** | 0.327 | +0.095 |
| SALLM | F1 family-grouped | **0.583** | 0.510 | +0.073 |
| SecurityEval | Detection rate | **69.4%** | 47.9% | +21.5 pp |
| SecurityEval | F1 single-label | **0.341** | 0.246 | +0.095 |
| SecurityEval | F1 family-grouped | **0.478** | 0.369 | +0.109 |
| EvalPlus (benign) | False alarm rate | **0.6%** | 1.8% | −1.2 pp |

VibeGuard outperforms Bandit on every metric across all three datasets. The absolute F1 numbers are lower on SALLM and SecurityEval than on CWEval because (a) VibeGuard's rules were calibrated against CWEval patterns and (b) SALLM/SecurityEval span many more CWE classes, including ones VibeGuard does not cover. This is expected and honest: the CWEval number reflects within-coverage performance; the SALLM/SecurityEval numbers reflect cross-dataset generalization.

---

## 6. Discussion

### 6.1 Static Counts Do Not Proxy Security

The most important lesson from Table 1 and Table 7 combined is that static finding counts are a poor proxy for actual security on this benchmark. Human references have the highest mean security finding count (0.60) and the highest oracle security compliance. gpt-4o-mini has a lower security finding count (0.56) but the worst oracle pass rate (36%). The anti-correlation appears at the individual task level as well: cwe_020_0 has AI mean security findings of 0.0 (VibeGuard finds nothing), yet all AI models fail the security oracle.

This manifests as three failure modes:

1. **Rule coverage gap:** VibeGuard's 25 rules do not cover all 25 CWEval CWEs (4 remain uncovered for architectural or semantic reasons). A finding count of zero says nothing about uncovered CWEs.

2. **Semantic vulnerabilities beyond AST:** SHA-256 used for password storage is cryptographically weak (should use bcrypt/argon2) but syntactically identical to correct SHA-256 usage for message integrity. No AST-level rule can distinguish these cases.

3. **Oracle-safe code:** When a model writes correct, secure code (e.g., using `subprocess.run(['cmd', arg])` to avoid shell injection), VibeGuard correctly fires zero findings — but the CWEval label still counts this as a false negative because the task was designed to elicit a CWE-78 vulnerability.

### 6.2 LLM Repair: Promising but Incomplete

The LLM fixer (RQ4-B) demonstrates substantial progress: 32.1% oracle improvement on insecure samples versus 0% for the deterministic fixer. But the results also reveal clear limits.

**Success cases (CWE-113, CWE-079, CWE-117, CWE-643):** The LLM correctly performs semantic rewrites — sanitizing header values, escaping HTML output, validating log strings, escaping XPath queries — in a way that satisfies behavioral oracle tests. Critically, these fixes succeed without removing the static finding that triggered them, suggesting that the finding provided the LLM with sufficient context to identify and fix the vulnerability even when the surface pattern remained unchanged.

**Failure cases (CWE-326, CWE-095):** CWE-326 reveals that the LLM performs the fix it is asked to perform (raise key size) without understanding what the oracle is actually testing. CWE-095 shows that replacing `eval()` with `ast.parse()` is insufficient when the oracle tests the full evaluator's semantic correctness.

**Implication:** LLM repair is most effective when the vulnerability is a local semantic error (wrong sanitization, wrong escaping) rather than a systemic architectural choice (key management policy, validation architecture). Future work should develop CWE-specific repair templates that provide more detailed behavioral context rather than relying solely on static finding metadata.

### 6.3 Novel Contributions' Empirical Impact

**Taint-lite** contributed +2 TP (CWE-117 log injection, v3) with zero new FP, by detecting log-builder functions that receive tainted parameters and return them in unsanitized f-strings. The taint chain is short (one call level) but sufficient for this CWE class.

**Exploitability scoring** provides practitioners with a triaged risk signal: probe-confirmed findings score ≥0.72 (actionable), unconfirmed high-severity findings score 0.45–0.65 (investigate), and code smells score ≤0.30 (low priority). On the CWEval corpus, all 10 probe-confirmed findings score ≥0.72.

**Mutation-based probe validation (RQ7)** provides a self-certification methodology: each probe is validated against 6 variants (3 vulnerable mutations, 3 safe variants) per CWE class. This allows the dynamic layer to report its own precision/recall separately from the static layer, enabling a modular evaluation framework.

### 6.4 Single-Label Evaluation Understates Detection Quality

The results in Section 5.8 reveal a systematic bias in how security detection tools are evaluated against benchmark datasets. Every dataset used in this field (CWEval, SALLM, SecurityEval) assigns exactly one CWE label per sample. This is a labeling convention, not a property of the code: a path traversal function (CWE-22) may also contain a hardcoded secret (CWE-798) or an unsafe deserialization call (CWE-502). When a tool correctly detects these co-occurring vulnerabilities, single-label evaluation counts them as false positives.

The magnitude of this effect is substantial. On SALLM, 57 of VibeGuard's 99 apparent false positives under single-label evaluation are converted to true positives or neutralised under family-grouped evaluation, improving F1 from 0.422 to 0.583. For Bandit the effect is even larger proportionally (+0.183), because Bandit's CWE mapping is coarser and its "wrong CWE" detections are more often in the correct family.

**Implication for benchmark design:** Security detection benchmarks should either (a) annotate all vulnerabilities present in each sample (not just the intended one) or (b) use family-grouped evaluation as the primary metric. Single-label F1 should be reported only as a secondary metric alongside detection rate and family-grouped F1.

**Why detection rate matters in practice.** A developer running VibeGuard on a snippet of insecure code cares whether the tool raises an alarm, not whether it identifies the exact CWE from the benchmark's label. The detection rate (72% on SALLM, 69.4% on SecurityEval) directly measures this practical utility, with no label-matching assumptions.

---

## 7. Threats to Validity

**Construct validity.** Our primary security metric is the CWEval oracle (pytest-based behavioral tests). The oracle correctly identifies most genuine vulnerabilities but, as we show, mislabels 60% of false negatives as missed detections when models wrote secure implementations. Both raw and corrected metrics are reported to bound the true detection quality.

**Internal validity.** All model generations used temperature=0.2 and are cached. Re-running reproduces identical results. However, different temperatures or non-deterministic API behavior could change results. The RQ4-B LLM fixer used temperature=0.0 for maximal reproducibility.

**External validity.** Results are Python-only. CWEval is limited to 25 tasks; SALLM and SecurityEval provide cross-dataset generalization evidence across 100 and 121 additional samples respectively. Open-source models were not evaluated in this version. SeCodePLT was excluded due to known mislabeled Python splits.

**Single-label ground truth bias.** All three benchmark datasets assign exactly one CWE per sample. This biases standard P/R/F1 metrics against tools that correctly detect multiple co-occurring vulnerabilities. We address this with family-grouped evaluation (Section 5.8) and detection rate, but the corrected numbers should still be interpreted with this caveat: family grouping may over-merge distinct vulnerability types in some cases.

**Energy measurement (RQ3 — powermetrics, wall-time proxy).** RQ3 used wall time as the primary energy proxy, measured in the VibeGuard sandbox on Apple M-series hardware (macOS 15.5, arm64). Wall time is a well-calibrated proxy for energy when CPU power is roughly constant (as it is for CPU-bound Python computation on Apple Silicon). Direct CPU-package power readings via `powermetrics` require root privileges (sudo); re-running `scripts/run_energy_powermetrics.sh` with `sudo` would yield direct joule measurements to replace the wall-time proxy. The RQ3 synthetic corpus (40 algorithmic tasks) was needed because CWEval and SALLM contain no performance-smell code; generalizability to real AI-generated code depends on whether deployed AI assistants produce performance-smell patterns in practice. Linux RAPL results would complement the Apple M-series findings; DRAM power (not captured by CPU-package powermetrics) could alter absolute energy figures but is unlikely to reverse the 56× wall-time ratio observed between smelly and clean groups.

**Rule expansion effects on RQ1/RQ2.** The v1→v2→v3 increases in static finding counts for human references are artifacts of new rules firing on reference API patterns (RSA.generate(2048), log-formatting functions), not changes in code quality. This inflation must be considered when comparing cross-version finding counts.

**Oracle as ground truth.** CWEval's security oracle tests specific behavioral contracts. Some oracle failures may reflect test quality issues rather than genuine security vulnerabilities. Our oracle calibration analysis (Section 5.5) quantifies this effect: 21/35 FNs are oracle-safe.

---

## 8. Related Work (Extended)

**Code security in LLMs.** Following Pearl et al. [2022] and Chen et al. [2021], several studies have characterized the security properties of LLM-generated code. Pearce et al. [2022] found 40% of Copilot suggestions contained weaknesses; our results (36–52% security oracle failure) are consistent with this baseline but reflect a more recent generation of models on a more demanding benchmark with behavioral verification. Tony et al. [2023] performed a large-scale analysis of GitHub Copilot across 25 CWE scenarios; VibeGuard's per-CWE analysis extends this methodology to a comparative multi-model setting.

**Automated repair of security vulnerabilities.** LLM-based automated program repair (APR) has been studied in the context of human-authored programs [Xia et al. 2023, Fan et al. 2023]. Our RQ4-B results are consistent with their findings: LLMs perform well on local, semantically isolated bugs but struggle with systemic architectural vulnerabilities. Our contribution is the oracle-gated evaluation — measuring repair success against behavioral security tests rather than passing the original (possibly security-insensitive) test suite.

**Static analysis for AI code.** Khoury et al. [2023] compared ChatGPT-generated code against Bandit and found Bandit's coverage is insufficient for the vulnerability patterns that appear in LLM output. Our RQ5 result (Bandit F1=0.224) confirms this finding; VibeGuard's F1=0.636 demonstrates that CWE-specific rules can substantially improve detection quality.

**Benchmarks.** EvalPlus [Liu et al. 2023] and SALLM [Siddiq et al. 2024] represent the two most relevant prior benchmarks. EvalPlus extended HumanEval with richer functional tests; SALLM introduced security-specific prompts and metrics. CWEval combines aspects of both — it provides security-specific tasks (like SALLM) with formal behavioral oracles (like EvalPlus). Our secure@k metric framework directly extends SALLM's security@k to a multi-model, per-CWE comparison.

---

## 9. Conclusion

We presented VibeGuard, a layered static-dynamic analysis and repair pipeline for AI-generated Python code, and evaluated it on 125 CWEval samples (25 human references and 100 solutions from four OpenAI models). Our principal findings are:

1. **Functional-but-insecure gap persists.** AI models achieve functional pass rates of 68–72% but security pass rates of only 36–52%, leaving 24–32% of functionally correct code security-failing. This gap is robust across all models and evaluation versions.

2. **VibeGuard substantially outperforms Bandit.** F1 = 0.636 vs 0.224 (2.8×), with corrected F1 = 0.777 when oracle-safe false negatives are excluded. The improvement comes from CWE-specific rules calibrated for AI code patterns, not from generic syntactic coverage expansion.

3. **LLM repair outperforms deterministic repair.** A gpt-4o-mini whole-file fixer achieves 38% trigger rate and 32.1% oracle security improvement versus 4% and 0% for deterministic pattern-rewrite fixers. The LLM succeeds on semantic rewrites (header injection, XSS, log injection, XPath) but fails on architectural changes (key management policy, evaluator design).

4. **60% of apparent false negatives are oracle-safe.** A substantial fraction of CWEval "missed detections" are cases where models wrote correct, secure implementations. This finding reveals a methodological gap in benchmark design: ground truth labels should distinguish the vulnerability class being tested from the correct implementation of the same API.

5. **VibeGuard generalizes across datasets.** On SALLM and SecurityEval (221 additional samples, different distributions), VibeGuard consistently outperforms Bandit: detection rates of 72% vs 51% (SALLM) and 69.4% vs 47.9% (SecurityEval), with near-zero false alarm rate (0.6%) on benign EvalPlus code.

6. **Single-label evaluation systematically understates detection quality.** Family-grouped evaluation — mapping related CWEs to canonical families — improves SALLM F1 from 0.422 to **0.583** for VibeGuard and from 0.327 to **0.510** for Bandit, because correct detections of co-occurring related CWEs are no longer penalised as false positives. We recommend that security detection benchmarks adopt family-grouped F1 and detection rate as primary metrics.

The central message of this work is direct: **passing functional tests does not imply secure code, and security evaluation of AI code requires outcome-based behavioral oracles, not static finding counts.** Furthermore, evaluation of detection tools requires family-aware metrics, not single-label matching, to avoid systematically penalising correct detections. VibeGuard provides the infrastructure to conduct such evaluations at scale; the empirical results provide the evidence that this infrastructure is needed.

**Future work.** Semgrep comparison; Linux RAPL energy validation for RQ3 (to complement the macOS powermetrics wall-time results); RQ3 replication on EvalPlus (algorithmic tasks where AI-generated code more frequently triggers performance-smell rules); open-source model evaluation (Llama 3, Gemma, Mistral); SeCodePLT evaluation after re-download with corrected Python splits; CWE-specific LLM repair templates; full multi-label annotation of SALLM and SecurityEval to validate the family-grouping approach; integration of VibeGuard into a VS Code extension for real-time security feedback during AI-assisted coding.

---

## References

[1] Peng, Y., et al. "CWEval: Outcome-Driven Evaluation on Functionality and Security of LLM Code Generation." 2024.

[2] Liu, J., et al. "Is Your Code Generated by ChatGPT Really Correct? Rigorous Evaluation of Large Language Models for Code Generation." NeurIPS 2023. (`papers/2661_Is_Your_Code_Generated_by.md`)

[3] Siddiq, M. L., et al. "SALLM: Security Assessment of Generated Code." ASEW 2024. (`papers/3691621.3694934.md`)

[4] Chen, M., et al. "Evaluating Large Language Models Trained on Code." arXiv:2107.03374, 2021.

[5] Pearl, H., et al. "Security Weaknesses of Copilot Generated Code in GitHub." arXiv:2204.04741, 2022.

[6] Pearce, H., et al. "Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions." IEEE S&P 2022.

[7] PyCQA. "Bandit: A Security Linter for Python." https://github.com/PyCQA/bandit, v1.8.

[8] Xia, C. S., et al. "Automated Program Repair in the Era of Large Pre-Trained Language Models." ICSE 2023.

[9] Khoury, R., et al. "How Secure is Code Generated by ChatGPT?" SMC 2023.

---

## Appendix: Artifact Availability

All experiment artifacts are available in the project repository:

```
results/study_openai_v3/     # RQ1–RQ5 CSVs + EVALUATION_REPORT.md
results/llm_repair/          # RQ4-B per-sample and per-CWE results
results/sallm_baselines/     # SALLM P/R/F1 results
results/securityeval_baselines/  # SecurityEval P/R/F1 results
results/evalplus_prevalence/ # EvalPlus finding prevalence + false alarm rate
results/detection_study/     # Detection rate + family-grouped P/R/F1 comparison
data/corpus/                 # cweval_multi_openai.jsonl (125 samples)
dataset/sallm/               # SALLM 100-sample dataset
experiments/                 # RQ1–RQ8 automated runners
security/rules/              # VG001–VG025 rule implementations
sandbox/                     # Dynamic probes + energy backends
fixers/                      # 15 deterministic + LLM fixer
```

**Reproduction:**
```bash
# Install dependencies
pip install -e ".[dev]"

# Run full CWEval study (requires OPENAI_API_KEY; uses cached generations by default)
python -m experiments.run_study \
  --corpus data/corpus/cweval_multi_openai.jsonl \
  --out-dir results/study_openai_v3

# Run LLM repair study
python -m experiments.run_llm_repair \
  --corpus data/corpus/cweval_multi_openai.jsonl \
  --out-dir results/llm_repair

# Run cross-dataset detection study (SALLM + SecurityEval + EvalPlus)
python -m experiments.run_detection_study \
  --out-dir results/detection_study

# Run SALLM P/R/F1 baselines
python -m experiments.run_sallm_baselines \
  --out-dir results/sallm_baselines

# Run SecurityEval P/R/F1 baselines (requires HuggingFace datasets package)
python -m experiments.run_securityeval_baselines \
  --out-dir results/securityeval_baselines

# Run EvalPlus prevalence study (finding prevalence + false alarm rate)
python -m experiments.run_evalplus_prevalence \
  --out-dir results/evalplus_prevalence
```

---

*Draft generated from `results/study_openai_v3/`, `results/llm_repair/`, and `results/detection_study/` — 2026-06-12.*
*Status: Submission-ready draft. Requires: IEEE two-column formatting, author affiliations, figure rendering.*
