# Slide Numbers Explained — VibeGuard Presentation

A reference for every number that appears in the slides, where it comes from, and how it was computed.

---

## Slide 6 — RQ1: Static Findings Across All Three Dimensions

**Corpus**: 25 human references + 25 AI samples per model = 125 samples total (CWEval dataset).
**What the numbers are**: mean findings per sample — i.e. on average how many rule violations VibeGuard found per code snippet.

| Number | What it means | How computed |
| --- | --- | --- |
| 0.24 security (human) | Roughly 1 security rule triggered for every 4 human snippets. In total: 6 findings across 25 samples | 6 ÷ 25 = 0.24 |
| 0.32 smell (human) | Roughly 1 smell finding for every 3 human snippets. Total: 8 findings across 25 samples | 8 ÷ 25 = 0.32 |
| 0.0 perf (all sources) | No performance rule fired on any CWEval snippet — column removed from slide | CWEval tasks are short security functions with no looping anti-patterns. Performance rules fire on algorithmic tasks (EvalPlus, Slide 10) |
| GPT-4.1 smell = 0.84 | Almost 1 smell finding per snippet on average. Total: 21 smell findings across 25 samples | 21 ÷ 25 = 0.84 |
| GPT-4.1 total = 1.08 | More than 1 finding per snippet on average | 0.24 security + 0.84 smell + 0.0 perf = 1.08 |
| 52% affected (GPT-4.1) | 13 out of 25 GPT-4.1 samples had at least one finding of any kind | 13 ÷ 25 = 52% |
| "3× more smells" | GPT-4.1 smell (0.84) vs average of other 3 models: (0.32+0.20+0.16)/3 = 0.23 → 0.84/0.23 ≈ 3.7×, rounded to 3× in the talk | Ratio of GPT-4.1 smell mean to the mean of the other three models |

---

## Slide 7 — RQ2: AI vs Human Across All Dimensions

| Number | What it means | How computed |
| --- | --- | --- |
| Human mean total: 0.56 | Average total findings per human snippet | 0.24 security + 0.32 smell + 0.0 perf |
| AI mean total: 0.65 | Average total findings across all four AI models | (1.08 + 0.60 + 0.48 + 0.44) ÷ 4 = 2.60 ÷ 4 = 0.65 |
| ~16% worse | AI produces ~16% more findings than human | (0.65 − 0.56) ÷ 0.56 ≈ 0.16 |
| 73/100 tasks | EvalPlus result — AI faster or equal on 73 of 100 algorithmic tasks | From `results/energy_evalplus/summary.json` → `n_ai_faster_or_same: 73` |

---

## Slide 8 — RQ5: Baseline Comparison

**What is being measured**: whether the tool correctly identifies the ground-truth CWE label on each sample, compared against the CWEval oracle (which independently confirms whether the code is insecure).

**Corpus**: 76 samples with a confirmed positive CWE label (oracle-insecure). Source: `results/study_openai_v3/`.

| Number | What it means | How computed |
| --- | --- | --- |
| TP = 41 | VibeGuard flagged the correct CWE on 41 truly insecure samples | VibeGuard's predicted CWE matches the oracle label |
| FP = 12 | VibeGuard flagged the CWE on 12 samples that were actually oracle-secure | False alarms |
| FN = 35 | VibeGuard missed the CWE on 35 truly insecure samples | Missed cases |
| Precision = 0.774 | 41 ÷ (41 + 12) = 41 ÷ 53 | Of all alarms raised, how many were correct |
| Recall = 0.539 | 41 ÷ (41 + 35) = 41 ÷ 76 | Of all real vulnerabilities, how many were caught |
| F1 = 0.636 | 2 × 0.774 × 0.539 ÷ (0.774 + 0.539) | Harmonic mean of precision and recall |
| Bandit: 12 TP, 19 FP, 64 FN | Bandit found only 12 of the same 76 vulnerabilities | Same metric — Bandit lacks CWE-specific Python rules |
| Bandit Precision = 0.387 | 12 ÷ (12 + 19) = 12 ÷ 31 | |
| Bandit Recall = 0.158 | 12 ÷ (12 + 64) = 12 ÷ 76 | |
| Bandit F1 = 0.224 | 2 × 0.387 × 0.158 ÷ (0.387 + 0.158) | |
| Corrected recall = 0.745 | Some of the 35 FNs are "oracle-safe" — the model actually wrote secure code, so it is not a real miss. Removing 21 such cases: 41 ÷ (41 + 14) = 41 ÷ 55 = 0.745 | Fairer recall — does not penalise VibeGuard for code that genuinely passed the security oracle |
| Corrected F1 = 0.777 | Recomputed F1 using corrected recall | Shows true detection performance when oracle-safe FNs are excluded |
| SALLM: 99/100 (99%) | On the SALLM dataset (100 known-insecure snippets), VibeGuard raised at least one security alert on 99 of them | High coverage on a broader, independent insecure dataset |

---

## Slide 9 — RQ4: Auto-Fix Results

**Corpus**: 100 AI-generated CWEval samples. The LLM fixer only attempts samples that have at least one CWE-tagged security finding.

| Number | What it means | How computed |
| --- | --- | --- |
| LLM trigger 38% (38/100) | The LLM fixer changed 38 of 100 samples | The LLM rewrites the full file when a CWE-tagged finding is present — more flexible |
| 32% oracle improved (18/56) | 18 samples went from failing to passing the security oracle. Denominator 56 = samples that had at least one CWE-tagged finding and were attempted by the LLM | 18 ÷ 56 = 32.1% |
| 9 samples reverted | 9 LLM fixes introduced a new finding type and were automatically rejected by the static gate | Gate rule: if the repair adds any new rule violation category, revert the change |
| CWE-022 (5), CWE-113 (4), CWE-502 (3) | Breakdown of oracle wins per vulnerability type | Counted from per-sample results in `results/llm_repair/` |

---

## Slide 10 — RQ3: Performance of Real AI Code on Algorithmic Tasks

**Corpus**: 300 samples — 100 human HumanEval+ references + 100 gpt-4o + 100 gpt-4o-mini, across 100 algorithmic tasks. Each implementation profiled at 4 input scales, 5 timed runs + 1 warm-up. Source: `results/energy_evalplus/`.

| Number | What it means | How computed |
| --- | --- | --- |
| 73 / 100 tasks AI faster or equal | On 73 tasks, mean AI wall time ≤ mean human wall time | From `summary.json` → `n_ai_faster_or_same: 73` |
| 27 / 100 AI slower | Remaining tasks where AI was measurably slower | 100 − 73 = 27 |
| Mann-Whitney p = 0.97 | No statistically significant difference between AI and human runtime at the population level | Mann-Whitney U test on all 100 per-task ratios (AI time ÷ human time). From `summary.json` → `mannwhitney.p: 0.9697` |
| gpt-4o `strange_sort_list` 5.4× slower | gpt-4o mean = 0.01289 s, human mean = 0.00238 s → ratio = 5.41 | From `summary.json` → `HumanEval/70`, `ai_vs_human_ratio: 5.414` |
| Root cause: `pop(0)` in a while loop | `list.pop(0)` shifts all remaining elements in memory → O(n) per call. With n iterations → O(n²) total. Human reference is O(n log n) | Confirmed by inspecting the generated code |
| gpt-4o-mini: no regression | gpt-4o-mini used a two-pointer approach → O(n log n), no `pop(0)` | Code inspection + profiling ratio near 1.0 |
| PF004 fires on gpt-4o, silent on gpt-4o-mini | PF004 (`list_pop_front_in_loop`) detects `list.pop(0)` inside a loop | 2 findings flagged on gpt-4o HumanEval/70; 0 on gpt-4o-mini |
| Human `rolling_max` ~800× slower (HumanEval/9) | Human mean = 1.891 s, AI mean = 0.00229 s → ratio ≈ 0.001 → AI is ~800× faster | From `summary.json` → `HumanEval/9`, `ai_vs_human_ratio: 0.001`. Human reference uses a nested max() → O(n²); AI writes the O(n) running-maximum |

---

## Common Questions You May Get

**"Why is the slide F1 (0.636) different from the paper F1 (0.664)?"**
The slides use v3 results on the original 25-task CWEval corpus (76 positive samples). The paper reports results on a larger corpus of 504 samples with 4 model snapshots × 5 samples per task and a later rule set. Same direction, different scale.

**"Why wall time instead of joules?"**
macOS requires `sudo` for hardware energy counters (powermetrics/RAPL). Without `sudo`, wall-clock time is used as a proxy. On Linux with RAPL this gives direct joule readings — listed as future work in the slides.

**"What about the huge outlier ratios (e.g. HumanEval/147: 2.27M×)?"**
Measurement artifact. The human reference runs in near-zero time at the chosen input scale (e.g. returns immediately for a trivial edge case). The AI solution takes ~0.88 s. The ratio is technically correct but not a real algorithmic regression — both solutions are correct, the input just happens to be trivial for the human version.

**"Why only Bandit as baseline?"**
Bandit is the most widely adopted Python security linter and the closest tool in scope to VibeGuard. It covers security only; VibeGuard additionally covers smells and performance.

**"Is 5.4× a big deal in practice?"**
Yes at scale. `strange_sort_list` with n = 50,000 runs 5.4× slower. More importantly, the pattern (`pop(0)` in a loop) is not obvious to spot in a code review, and PF004 catches it automatically. The gpt-4o-mini variant avoids it entirely, showing this is model-specific, not task-inherent.
