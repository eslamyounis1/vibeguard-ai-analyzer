# VibeGuard: Detecting Security Vulnerabilities, Code Smells, and Performance Issues in AI-Generated Python Code

**ASE 2026 | Paris Lodron University of Salzburg**
**Total time: 10 minutes | 3 Presenters**

---

## Presenter 1 — Motivation & Approach (3.5 min)

---

### Slide 1 — Title (30s)

**VibeGuard: Detecting Security Vulnerabilities, Code Smells, and Performance Issues in AI-Generated Python Code**

ASE 2026 | Paris Lodron University of Salzburg

*[Names of all 3 presenters]*

---

### Slide 2 — Problem & Motivation (1 min)

**Is AI-generated code secure, clean, and energy-efficient?**

- AI code generation is exploding (GPT-4o, Copilot, etc.) — functional correctness is not enough
- Three critical concerns:
  - **Security** — are AI models introducing vulnerabilities?
  - **Smells** — do AI models write maintainable, idiomatic code?
  - **Energy** — do performance anti-patterns carry a real runtime cost?
- Prior work focused on correctness — security and quality largely ignored
- **Gap**: no unified, purpose-built analyzer addressing all three dimensions

---

### Slide 3 — VibeGuard Architecture (1 min)

**A unified, multi-layer analyzer for AI-generated Python code**

```
┌─────────────────────────────────────────────────────────────────┐
│                        INPUT LAYER                              │
│         AI-generated Python code  +  Human reference code      │
│         (CWEval · SALLM · EvalPlus HumanEval+ 300 samples)     │
└───────────────────────────┬─────────────────────────────────────┘
                            │
            ┌───────────────▼───────────────┐
            │      PILLAR 1: Static Analysis │
            │  security/   smell/   perf/    │
            │  40 rules    9 rules  4 rules  │
            │  VG001–VG040   PF001–PF004     │
            │  Taint tracking (SSRF + XSS)   │
            └───────────────┬───────────────┘
                            │  Findings
            ┌───────────────▼───────────────┐
            │   PILLAR 2: Dynamic Probing   │
            │  sandbox/security_prober.py    │
            │  10 probes: SQL · CMD · Path   │
            │  XSS · Header · Log · Key ...  │
            │  sandbox/profiler.py           │
            │  CPU · Memory · Wall · Energy  │
            └───────────────┬───────────────┘
                            │  Verified findings + runtime profile
            ┌───────────────▼───────────────┐
            │     PILLAR 3: Auto-Fix        │
            │  fixers/  ← deterministic      │
            │  (15 rules with pattern fixes) │
            │  fixers/llm_fixer.py ← LLM    │
            │  (all 53 rules eligible)       │
            │  Before/after profiling delta  │
            └───────────────┬───────────────┘
                            │  Fixed code + CPU/memory/energy delta
            ┌───────────────▼───────────────┐
            │   PILLAR 4: Evaluation        │
            │  experiments/  RQ1–RQ5         │
            │  Precision · Recall · F1       │
            │  Energy · Oracle · Baselines   │
            └───────────────────────────────┘
```

- **Modules**: `security/` · `sandbox/` · `fixers/` · `orchestrator/` · `experiments/`
- **53 rules** total: 40 security (VG001–VG040) + 9 smell + 4 performance (PF001–PF004)
- Each pillar is independently usable via CLI (`vibeguard scan --profile`, `--fix --profile`)

---

### Slide 4 — Research Questions (1 min)

| RQ | Dimension | Question |
|----|-----------|----------|
| RQ1 | Security + Quality | How many vulnerabilities and smells does VibeGuard find in AI code? |
| RQ2 | Comparison | Does AI code have more issues than human-written code? |
| RQ3 | Performance | How does the runtime efficiency of AI-generated code compare to human-written code on algorithmic tasks, and can VibeGuard detect observed inefficiencies? |
| RQ4 | Fix | How effective is auto-fix at resolving detected issues? |
| RQ5 | Baseline | How does VibeGuard compare to state-of-the-practice static analyzers? |

---

## Presenter 2 — Results (4 min)

---

### Slide 5 — Dataset & Setup (30s)

**Two corpora — security tasks and algorithmic tasks**

| Corpus | Samples | Purpose |
|--------|---------|---------|
| CWEval (4 models) | 25 human + 100 AI | Security + smells (RQ1–RQ2, RQ4–RQ5) |
| SALLM | 100 AI | Security detection coverage |
| EvalPlus HumanEval+ | 100 human + 200 AI | Performance study (RQ3) |

- **Security models**: GPT-4.1, GPT-4.1-mini, GPT-4o, GPT-4o-mini
- **Performance models**: GPT-4o, GPT-4o-mini (100 algorithmic tasks, 300 samples total)
- EvalPlus selected for algorithmic diversity — tasks where complexity tradeoffs are observable

---

### Slide 6 — RQ1: Static Findings Across All Three Dimensions (1 min)

**AI code carries more issues — smells drive the gap**

| Source | Security | Smell | Total | % Affected |
|--------|----------|-------|-------|------------|
| Human | 0.24 | 0.32 | 0.56 | 44% |
| GPT-4.1 | 0.24 | **0.84** | **1.08** | **52%** |
| GPT-4.1-mini | 0.28 | 0.32 | 0.60 | 40% |
| GPT-4o | 0.28 | 0.20 | 0.48 | 40% |
| GPT-4o-mini | 0.28 | 0.16 | 0.44 | 36% |

> Note: Performance rules fire on algorithmic tasks (EvalPlus, Slide 10) — not on short security functions like CWEval.

> Key finding: GPT-4.1 generates **3× more smells** than other models — more capable does not mean cleaner code.

---

### Slide 7 — RQ2: AI vs Human Across All Dimensions (30s)

**AI code is ~16% worse overall on security tasks — smells drive the gap**

- Human mean total: **0.56** | AI mean total: **0.65**
- Security findings: comparable between AI and human
- **Smell findings drive the quality gap** — AI models favour verbose, non-idiomatic patterns
- On algorithmic tasks (EvalPlus): AI is faster or equal on **73/100 tasks** — no general efficiency gap

---

### Slide 8 — RQ5: Baseline Comparison (1 min)

**VibeGuard outperforms Bandit across all metrics**

| Tool | Precision | Recall | F1 |
|------|-----------|--------|----|
| VibeGuard | **0.774** | **0.539** | **0.636** |
| Bandit | 0.387 | 0.158 | 0.224 |

- VibeGuard: 41 TP, 12 FP, 35 FN
- Corrected recall (oracle-safe FNs excluded): **0.745** | Corrected F1: **0.777**
- SALLM: **99/100** samples detected (99%)

> We evaluate against Bandit — the most widely adopted state-of-the-practice Python security linter — as our representative baseline. Bandit covers security only; VibeGuard additionally covers smells and performance.

---

### Slide 9 — RQ4: Auto-Fix Results (30s)

**LLM-based fixer resolves real vulnerabilities — with profiler-validated improvements**

| Fixer | Trigger Rate | Oracle Improved |
|-------|-------------|-----------------|
| LLM (gpt-4o-mini) | **38% (38/100)** | **32% (18/56)** |

- Top oracle wins: CWE-022 path traversal (5), CWE-113 header injection (4), CWE-502 pickle (3)
- Fixes span all three dimensions: security patches + smell refactors
- 9 samples reverted (LLM introduced new findings)
- **Before/after profiling delta** reported for every fix: CPU time Δ, wall time Δ, memory Δ, energy Δ
  - Example: fixing `hashlib.md5` → CPU −1.8%, memory −68 B, energy −0.0025 J

---

### Slide 10 — RQ3: Performance of Real AI Code on Algorithmic Tasks (30s)

**AI is generally efficient — but model-specific anti-patterns emerge**

- Corpus: 100 EvalPlus HumanEval+ tasks · 300 samples (100 human + 100 gpt-4o + 100 gpt-4o-mini)
- Each implementation profiled at 4 input scales (n = 500 → 100 000), 5 timed runs

| Outcome | Tasks |
|---------|-------|
| AI faster or equal to human | **73 / 100** |
| AI slower than human | 27 / 100 |
| Largest meaningful regression | gpt-4o `strange_sort_list` **5.4×** slower |

- **Root cause**: gpt-4o used `lst.pop(0)` in a while loop — O(n) shift per iteration → O(n²) total
- gpt-4o-mini used a two-pointer approach → O(n log n) — no regression
- **New rule PF004** (`list_pop_front_in_loop`) catches this pattern; fired on gpt-4o, silent on gpt-4o-mini
- Bonus finding: EvalPlus human reference for `rolling_max` is O(n²) — both AI models wrote O(n)

---

## Presenter 3 — Discussion & Conclusion (2.5 min)

---

### Slide 11 — Key Takeaways (1 min)

**Three dimensions, five findings**

- **Security**: AI models pass functional tests but 36–52% produce insecure code
- **Smells**: GPT-4.1 generates 3× more smells — capability does not guarantee cleanliness
- **Performance**: AI matched or beat humans on **73/100 tasks** — but gpt-4o introduced a `pop(0)` O(n²) regression (5.4×) caught by new rule PF004
- **Fix**: LLM auto-fix resolves real vulnerabilities (38% trigger rate, 32% oracle gain)
- **Comparison**: VibeGuard F1=0.636 vs Bandit F1=0.224 — purpose-built, multi-dimensional rules matter

---

### Slide 12 — Limitations & Threats to Validity (45s)

**Honest boundaries of our study**

- Static analysis only: cannot catch architectural SSRF or semantic crypto misuse (e.g., SHA-256 for passwords)
- CWEval oracle is binary — may miss partially fixed vulnerabilities
- RQ3 profiling on macOS (Apple M-series); no RAPL hardware energy counter — wall time used as proxy
- EvalPlus human references are not always optimal (rolling_max O(n²)) — complicates AI vs human comparison
- 2 OpenAI models for RQ3, 4 for RQ1–RQ2 — results may not generalize to open-source LLMs (Llama, Gemini)

---

### Slide 13 — Conclusion & Future Work (45s)

**VibeGuard: the first unified static analyzer for AI-generated Python code**

- Covers **security, quality, and performance** in a single extensible rule engine
- **53 rules** (40 security + 9 smell + 4 performance PF001–PF004), open-source
- PF004 (`list_pop_front_in_loop`) motivated by and validated on real AI-generated code
- Full pipeline: static → dynamic probing → profiled auto-fix → evaluation
- F1=0.636 vs Bandit F1=0.224 — purpose-built, multi-dimensional rules matter

**Future work:**
- Semgrep integration for deeper inter-procedural analysis
- More LLM providers (Llama, Gemini, Claude) across both security and performance corpora
- Linux + RAPL energy measurement for hardware-accurate RQ3
- LLM-guided rule synthesis from CVE databases and observed AI coding patterns

---

## Time Budget

| Presenter | Section | Slides | Time |
|-----------|---------|--------|------|
| Presenter 1 | Motivation + Architecture + RQs | 1–4 | 3.5 min (Slide 3 = architecture diagram) |
| Presenter 2 | RQ1–RQ5 Results | 5–10 | 4.0 min |
| Presenter 3 | Discussion + Conclusion | 11–13 | 2.5 min |
| **Total** | | **13 slides** | **10 min** |

---

## Speaker Notes

### Slide 2 (Motivation)
Open with the observation that developers are increasingly trusting AI tools to write production code — but functional tests alone cannot guarantee that code is safe, clean, or efficient. VibeGuard addresses exactly this gap.

### Slide 3 (Architecture)
Walk through the diagram top-to-bottom in one pass: *"Code enters at the top, passes through four pillars — static analysis, dynamic probing, auto-fix, and evaluation — each independently usable via CLI."* Note that the input layer now includes EvalPlus HumanEval+ for RQ3 in addition to CWEval and SALLM. Pillar 1 now has 4 performance rules including PF004, which was directly motivated by observing gpt-4o's behaviour on real algorithmic tasks.

### Slide 6 (RQ1)
Emphasise the GPT-4.1 outlier: despite being the most capable model, it produces the most smells. This challenges the assumption that more powerful models write better-quality code.

### Slide 8 (RQ5)
Pre-empt the "why only Bandit?" question: *"We chose Bandit as our representative baseline because it is the most widely adopted Python security linter and the closest tool in scope to VibeGuard."*

### Slide 9 (RQ4)
Point out that the fix pipeline is now fully closed-loop: every fix produces a before/after profiling report (CPU, memory, energy). This directly addresses the proposal's requirement to "validate optimizations using profiling results" — no longer a gap.

### Slide 10 (RQ3)
Lead with the nuanced finding: *"AI models are generally as efficient as human programmers on algorithmic tasks — they matched or beat the human reference on 73 of 100 tasks."* Then pivot: *"But we found one concrete, reproducible regression. gpt-4o's implementation of strange_sort_list used pop(0) inside a while loop — every pop(0) shifts all remaining elements, turning an O(n log n) problem into O(n²). At n=50,000 this was 5.4× slower than the human solution."* Point out that gpt-4o-mini avoided this entirely. Close with: *"This is exactly the kind of pattern VibeGuard's new PF004 rule now detects — motivated directly by observing real AI-generated code, not by constructing synthetic examples."*

### Slide 13 (Conclusion)
End with a single strong sentence: *"VibeGuard shows that AI-generated code needs a new class of analyzer — one that understands security, quality, and energy together."*
