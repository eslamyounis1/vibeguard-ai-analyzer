---
marp: true
theme: default
paginate: true
backgroundColor: "#ffffff"
color: "#1a1a2e"
style: |
  section {
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 26px;
  }
  h1 { color: #1a237e; font-size: 1.8em; border-bottom: 3px solid #3949ab; padding-bottom: 0.2em; }
  h2 { color: #283593; font-size: 1.3em; }
  h3 { color: #3949ab; font-size: 1.1em; }
  table { font-size: 0.72em; width: 100%; }
  th { background-color: #3949ab; color: white; padding: 5px 10px; }
  td { padding: 4px 10px; border-bottom: 1px solid #ddd; }
  tr:nth-child(even) td { background-color: #f5f7ff; }
  code { background: #f0f2ff; color: #c62828; padding: 2px 6px; border-radius: 4px; }
  blockquote { background: #e8eaf6; border-left: 4px solid #3949ab; padding: 8px 14px; border-radius: 4px; margin: 8px 0; }
---

<!-- SLIDE 1 — TITLE -->

# VibeGuard
## Empirical Study of Security, Quality & Repair in AI-Generated Python Code

**ASE 2026 — Paris Lodron University of Salzburg**

Haylemicheal Mekonnen · Eslam Younis · Elbetel Reta

> _"Can we trust the code AI writes?"_

---

<!-- SLIDE 2 — PROBLEM & RESEARCH QUESTIONS -->

# Problem & Research Questions

**"Vibe coding"** — generating code fast with minimal review — introduces three risks:

- **Security:** eval injection, weak crypto, hardcoded secrets, SSRF, XSS ...
- **Quality:** code smells, high complexity, structural deficiencies
- **Performance:** energy-inefficient patterns, unnecessary CPU cycles

**Do existing static tools catch these in AI-generated code?**

| RQ | Question |
|----|---------|
| RQ1 | How prevalent are findings in AI vs. human-reference code? |
| RQ2 | Do AI solutions have more findings than secure human references? |
| RQ4 | How often does auto-fix remove findings and improve security? |
| RQ5 | How does VibeGuard compare to Bandit on CWE-labeled vulnerabilities? |

---

<!-- SLIDE 3 — ARCHITECTURE -->

# VibeGuard Architecture

```
Input Code
    │
    ├─► Static Analysis  (security/ — 25 security + 9 smell + 3 perf rules, AST-based)
    │
    ├─► Dynamic Analysis (sandbox/ — isolated subprocess, CPU / memory / energy)
    │
    ├─► Auto-Fix Engine  (fixers/ — deterministic rewrites + LLM-powered repair)
    │                       safety-gated: reverts if new findings are introduced
    ├─► Orchestrator     (static ↔ dynamic corroboration, before/after comparison)
    │
    └─► Output: terminal report / JSON / VS Code Problems / CI exit codes
```

**25 security rules (VG001–VG025):** eval/exec, hardcoded secrets, weak hash, SQL injection,
path traversal, SSRF, XSS, XPath injection, unsafe YAML/pickle, TLS bypass, log injection,
HTTP header injection, weak crypto key (NIST < 3072 bits), ReDoS, URL domain bypass, and more.

---

<!-- SLIDE 4 — BENCHMARK & METHODOLOGY -->

# Benchmark & Methodology

### CWEval Benchmark
- 25 Python security-oriented tasks, each with **functionality + security pytest oracles**
- Ground truth = oracle pass/fail (not static warning counts)

### Corpus — 125 samples

| Source | n |
|--------|---|
| Human secure references | 25 |
| openai:gpt-4o-mini / gpt-4o / gpt-4.1-mini / gpt-4.1 | 25 each |

### Baselines
- **Bandit** — Python security linter
- VibeGuard evaluated across 3 ruleset versions (v1: 19 rules → v3: 25 rules)

---

<!-- SLIDE 5 — RQ1 & RQ2: PREVALENCE -->

# RQ1 & RQ2 — Issue Prevalence: AI vs. Human

Mean static findings per sample (v3, 25-rule ruleset):

| Source | Security | Code Smell | Total | % Any Finding |
|--------|----------|-----------|-------|---------------|
| Human (secure ref) | 0.60 | 0.32 | **0.92** | 68% |
| gpt-4.1 | 0.48 | **0.84** | **1.32** | 68% |
| gpt-4.1-mini | 0.56 | 0.32 | **0.88** | 60% |
| gpt-4o / gpt-4o-mini | 0.52–0.56 | 0.16–0.20 | **0.72** | 56% |

**Key findings:**
- Human references now exceed AI models in raw security finding count — security-oriented reference code exercises more flagged API surfaces
- AI and human converge at ~0.91 total findings (RQ2)
- **Static finding count is a poor proxy for actual security** — oracle results tell a different story

---

<!-- SLIDE 6 — THE CORE FINDING: FUNCTIONAL BUT INSECURE -->

# The Core Finding: Functional But Insecure

CWEval pytest oracle results — does the code actually work AND stay secure?

| Model | Functional | Security | Both | Functional-Only (INSECURE) |
|-------|:----------:|:--------:|:----:|:--------------------------:|
| gpt-4.1 | 18/25 **72%** | 13/25 **52%** | 12/25 | **6 samples** |
| gpt-4.1-mini | 18/25 **72%** | 12/25 **48%** | 12/25 | **6 samples** |
| gpt-4o | 18/25 **72%** | 10/25 **40%** | 10/25 | **8 samples** |
| gpt-4o-mini | 17/25 **68%** | 9/25 **36%** | 9/25 | **8 samples** |

> All models achieve ~70% functional correctness.
> Security correctness lags by **20–36 percentage points.**
> **Code that passes tests and appears to work is not necessarily safe.**

---

<!-- SLIDE 7 — RQ5: TOOL COMPARISON -->

# RQ5 — VibeGuard vs. Bandit

Detection quality progression (21 CWE classes, 100 AI samples):

| Version | Rules | TP | FP | FN | Precision | Recall | F1 |
|---------|:-----:|:--:|:--:|:--:|:---------:|:------:|:--:|
| v1 | 19 | 8 | 19 | 20 | 0.296 | 0.286 | 0.291 |
| v2 | 24 | 27 | 12 | 49 | 0.692 | 0.355 | 0.470 |
| **v3** | **25** | **41** | **12** | **35** | **0.774** | **0.539** | **0.636** |
| Bandit | — | 12 | 19 | 64 | 0.387 | 0.158 | 0.224 |

VibeGuard v3: **2× precision**, **3.4× recall**, **2.8× F1** vs. Bandit.

**Oracle calibration:** 21 of 35 FNs (60%) are **oracle-safe** — AI models wrote correct secure code that the benchmark still labels as a miss. Corrected recall = **0.745**, corrected F1 = **0.777**.

---

<!-- SLIDE 8 — RQ4: AUTO-FIX -->

# RQ4 — Auto-Fix Effectiveness

Two repair strategies on 100 AI CWEval samples:

| Metric | Deterministic | LLM (gpt-4o-mini) |
|--------|:---:|:---:|
| Trigger rate | 4% (4/100) | **38% (38/100)** |
| Safety gate passed | 4/4 (100%) | 38/38 (100%) |
| Oracle security improved | **0/56 (0%)** | **18/56 (32.1%)** |

**Top LLM repair wins:** CWE-113 HTTP header injection (4/4), CWE-79 XSS (2/2), CWE-117 log injection (2/2), CWE-502 unsafe deserialization (3/4), CWE-22 path traversal (5/8).

**Key tension discovered:**
> Static finding removal **≠** oracle security.
> CWE-326: LLM raised key size to 4096 bits, removed all findings — oracle still fails.
> CWE-22/113/79: LLM passed oracle **without** removing the static finding.
> Both metrics are needed to fully characterise repair quality.

---

<!-- SLIDE 9 — KEY FINDINGS SUMMARY -->

# Key Findings Summary

| # | Finding |
|---|---------|
| 1 | All models produce functionally plausible code (~68–72%) |
| 2 | Security correctness lags functional by 20–36 pp — the **functional-but-insecure gap** |
| 3 | Newer/larger models are measurably more secure: gpt-4.1 (52%) vs gpt-4o-mini (36%) |
| 4 | gpt-4.1 produces the **most code smells** (0.84/sample) despite best security score |
| 5 | VibeGuard F1: **0.291 → 0.470 → 0.636** across three ruleset iterations |
| 6 | VibeGuard vs Bandit: F1 **0.636 vs 0.224**; corrected F1 **0.777** |
| 7 | Deterministic repair: 4% trigger rate, **0%** oracle improvement |
| 8 | LLM repair: 38% trigger rate, **32.1%** oracle improvement |
| 9 | 60% of FNs are oracle-safe — correct secure code mislabeled by the benchmark |
| 10 | **Static silence does not imply security** |

---

<!-- SLIDE 10 — CONCLUSION & FUTURE WORK -->

# Conclusion & Future Work

**VibeGuard delivers:**
- A 25-rule AST security analyzer with F1 = **0.636** (2.8× Bandit), corrected F1 = **0.777**
- Empirical evidence: passing tests does not mean secure code
- Dual repair pipeline: deterministic (fast, safe) + LLM (38% trigger, 32.1% oracle gain)
- Reproducible harness: corpus + pytest oracles + baselines + auto-fix

**Limitations:**
- Python only; 25 tasks (exploratory, not confirmatory)
- RQ3 energy study requires Linux + RAPL (macOS linear proxy not credible)
- CWE-327/918 FNs require semantic / inter-procedural data-flow analysis

**Future work:**
- Expand to SeCodePLT and EvalPlus datasets; more LLM models (Claude, Gemini, Llama)
- Add Semgrep baseline; data-flow analysis for SSRF/injection chains
- Higher-fidelity energy measurement with CodeCarbon / RAPL on Linux

> _Security evaluation of AI code must use **outcome-based oracles**, not static counts alone._
