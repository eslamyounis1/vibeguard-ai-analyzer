# VibeGuard: AI Code Quality, Energy, and Security Analyzer

> ASE 2026 — Paris Lodron University of Salzburg
> **Authors:** Haylemicheal Mekonnen, Eslam Younis, Elbetel Reta

---

## Table of Contents

- [Problem Definition](#problem-definition)
- [Objectives](#objectives)
- [System Architecture](#system-architecture)
- [Key Components](#key-components)
- [Expected Output](#expected-output)
- [Current Stage](#current-stage)
- [Team](#team)

---

## Problem Definition

AI-assisted programming tools have popularized "vibe coding" — generating code rapidly with minimal manual review. While this accelerates development, it consistently produces code that suffers across three critical dimensions:

- **Code Quality:** AI-generated code frequently contains structural deficiencies such as redundant logic, duplicated patterns, and overly complex constructs that degrade maintainability and increase technical debt.
- **Energy & Performance:** Generated code often lacks efficiency awareness, leading to unnecessary CPU cycles, elevated memory consumption, and increased energy usage — a growing concern at both cloud and edge scale.
- **Security & Privacy:** AI models generate code from statistical patterns rather than security-aware reasoning, resulting in subtle yet pervasive vulnerabilities including unsafe input handling, hardcoded credentials, and insecure API usage.

Without dedicated tooling to detect and remediate these issues, AI-generated code deployed in production systems carries significant quality, performance, and security risks.

---

## Objectives

- Detect and classify code smells in AI-generated code
- Analyze energy consumption and identify performance bottlenecks
- Identify security and privacy risks
- Provide automated suggestions or refactored code
- Improve overall code quality, efficiency, and reliability

---

## System Architecture

VibeGuard is composed of five layered components that work in sequence from input ingestion through to output reporting:

```
┌─────────────────────────────────────────┐
│             Input Layer                 │
│         Accepts source code             │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│         Static Analysis Layer           │
│  • Parses code into AST                 │
│  • Detects code smells & vulnerabilities│
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│         Dynamic Analysis Layer          │
│  • Executes code in a controlled sandbox│
│  • Profiles CPU, memory, execution time │
│  • Estimates energy consumption         │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│          Optimization Layer             │
│  • Rule-based & AI-assisted improvements│
│  • Validates optimizations via profiling│
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│            Output Layer                 │
│  • Generates reports & optimized code   │
└─────────────────────────────────────────┘
```

---

## Key Components

### Code Smell Detector
Identifies inefficient or poorly structured patterns such as redundant loops, duplicated logic, unused variables, and overly complex constructs.

### Energy Efficiency Analyzer
Measures execution time, CPU usage, and memory consumption to estimate energy usage and detect performance hotspots.

### Security & Privacy Analyzer
Detects vulnerabilities such as unsafe input handling, hardcoded secrets, insecure API usage, and risky functions (e.g., `eval`).

### Profiling Engine
Uses runtime profilers to identify bottlenecks and validate performance issues detected during static analysis.

### Suggestion & Auto-Fix Engine
Generates optimized code and explanations, with the option to automatically refactor inefficient or unsafe code.

---

## Expected Output

| Output | Description |
|---|---|
| **Analysis Report** | Detected code smells, energy/performance metrics, and security/privacy issues |
| **Optimization Suggestions** | Clear, actionable recommendations with explanations |
| **Refactored Code** | Improved version of the original submitted code |
| **Comparative Metrics** | Before vs. after performance and energy usage statistics |

---

## Current Stage

VibeGuard is currently in a **working, end-to-end stage**.

**What is available now:**
- Security, code-quality, and performance scanning for Python projects (static analysis)
- Runtime profiling through a sandbox API (self-time CPU, memory, estimated energy)
- **Automatic safe fixes** for several issue classes (`vibeguard scan --fix`)
- **Orchestration pipeline** that corroborates static performance findings with measured runtime cost
- **Comparative before/after metrics** (security, performance, energy) for proposed fixes
- Benchmarking tools to measure detection quality (Precision / Recall / F1)

**What comes next:**
- More auto-fixers (string-concat-in-loop, nested-loop restructuring)
- Optional AI-assisted refactoring on top of the deterministic fixers
- Higher-fidelity energy measurement (RAPL / CodeCarbon)

---

## Installation

```bash
pip install -e .
```

Requires Python 3.10+. No third-party dependencies for the core tool.

---

## Usage

### Scan a file or directory

```bash
vibeguard scan ./project
vibeguard scan app/main.py
```

### Output formats

```bash
# Human-readable terminal output (default)
vibeguard scan ./project --format text

# Structured JSON (for CI pipelines, dashboards, etc.)
vibeguard scan ./project --format json
```

### Filter by severity

```bash
# Report only HIGH and above
vibeguard scan ./project --severity high

# Report MEDIUM and above
vibeguard scan ./project --severity medium
```

### Save to a file

```bash
vibeguard scan ./project --output report.json --format json
vibeguard scan ./project --output report.txt
```

### Apply automatic fixes

VibeGuard can rewrite a subset of findings into safe, behavior-aware fixes.
Every fix is verified by re-scanning the result, and is only applied when it
does not introduce new findings.

```bash
# Preview changes as a unified diff (nothing is written)
vibeguard scan ./project --fix --dry-run

# Apply fixes in place
vibeguard scan ./project --fix

# Machine-readable fix report (includes diffs)
vibeguard scan ./project --fix --dry-run --format json
```

Currently auto-fixable rules:

| Rule | Fix |
|---|---|
| `weak_hash_algorithm` | `hashlib.md5/sha1` → `hashlib.sha256` |
| `unsafe_yaml_load` | `yaml.load(x)` → `yaml.safe_load(x)` |
| `tls_verification_disabled` | `verify=False` → `verify=True` |
| `assert_used_for_validation` | `assert cond, msg` → `if not (cond): raise AssertionError(msg)` |
| `string_concat_in_loop` | loop `s += x` → list append + `"".join(...)` (energy) |
| `membership_in_loop` | `x in [a, b, c]` → `x in {a, b, c}` (O(1) lookups) |

The two performance fixers can additionally be validated against a task's own
test suite via the orchestrator's `compare_fix(..., tests=...)`, which reports
`behavior_verified` only when the tests pass both before and after the fix.

### Other flags

```bash
--no-snippet      Exclude source code snippets from findings
--quiet           Suppress informational messages when using --output
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Scan completed — no findings above selected threshold |
| `1`  | Scan completed — findings detected |
| `2`  | Operational error or invalid usage |

---

## Implemented Security Rules (Phase 1)

| Rule ID | Title | Severity |
|---------|-------|----------|
| VG001 | Use of `eval()` | CRITICAL |
| VG002 | Use of `exec()` | CRITICAL |
| VG003 | Hardcoded Secret | HIGH |
| VG004 | Insecure Randomness | MEDIUM |
| VG005 | Dangerous Subprocess Usage (`shell=True`) | HIGH |
| VG006 | Pickle Deserialization | HIGH |
| VG007 | Assert Used for Security Check | MEDIUM |
| VG008 | Weak Hash Algorithm | HIGH |
| VG009 | OS Shell Execution | HIGH |
| VG010 | Unsafe YAML Deserialization | HIGH |
| VG011 | TLS Verification Disabled | HIGH |
| VG012 | Debug Mode Enabled | MEDIUM |
| VG013 | Dynamic SQL Query Construction | HIGH |

The security analyzer now covers unsafe dynamic execution, secrets, weak cryptography, shell execution, unsafe deserialization, TLS bypasses, debug server configuration, and SQL query construction risks.

Security findings also include optional professional metadata for reports and editor integrations: confidence, risk score, CWE, OWASP category, impact, and remediation guidance.

To suppress an intentional finding, add an inline or previous-line ignore comment:

```python
# vibeguard: ignore sql_query_construction
cursor.execute(query)
```

---

## Example Output

```
[HIGH] VG001 Use of eval()
  File: app/main.py:14
  Code: result = eval(user_input)
  Message: Use of eval() is insecure and may allow arbitrary code execution.

[HIGH] VG003 Hardcoded Secret
  File: app/config.py:3
  Code: password = "hunter2"
  Message: Variable 'password' appears to contain a hardcoded secret.

Scanned 4 file(s). Found 3 issue(s): 2 high, 1 medium, 0 low.
```

---

## Project Structure

```
.
├── security/           Security & static analysis (DETECTION ONLY)
│   ├── cli/            Command-line interface (scan, --fix)
│   ├── core/           Scanner orchestration
│   ├── analyzers/      security / smells / performance analyzers
│   ├── rules/          security / smells / performance rules
│   ├── models/         Finding and ScanResult data models
│   ├── reporters/      Text and JSON output formatters
│   ├── api/            Security-only HTTP API (/analyze)
│   └── utils/          File traversal helpers
├── fixers/             Auto-fix (optimization) engine + per-rule fixers
│                       (security + energy-relevant performance fixers)
├── sandbox/            Dynamic analysis — ALL runtime metrics live here
│   ├── sandbox_runner.py   Isolated runner: profile mode + clean measure mode
│   ├── profiler.py         Subprocess client (profile_code / measure_code)
│   ├── energy/             Pluggable EnergyMeter backends (RAPL, CodeCarbon,
│   │                       powermetrics, linear proxy) + get_meter("auto")
│   └── main.py             Sandbox HTTP API (/profile)
├── orchestrator/       Cross-cutting layer (depends on security + sandbox)
│   ├── pipeline.py     Static<->dynamic corroboration + before/after comparison
│   └── api.py          Orchestration HTTP API (/fix, /analyze-profile, /compare)
├── corpus/             Study corpus: schema, JSONL storage, dataset loaders,
│                       LLM providers (cached), build.py CLI
└── experiments/        Research harness: measure.py (stats), baselines.py
                        (tool comparison), run_study.py (RQ1–RQ5 outputs)
```

**Layer boundaries:** runtime metrics (energy, memory, CPU, time) live only in
`sandbox/`; `security/` contains security/static *detection* only; `fixers/`
holds all auto-fixes; the `orchestrator/` is the single layer permitted to
combine detection with dynamic measurement (and hosts the `/fix` endpoint).

Additional analyzers plug in as siblings under `analyzers/` and `rules/`.

---

## Research Harness (empirical study)

VibeGuard doubles as a research instrument for studying how secure, clean, and
energy-efficient AI-generated code is, and how much is auto-repairable. Heavy
dependencies are optional extras so the core tool stays dependency-free:

```bash
pip install -e ".[experiments]"     # pandas, scipy, matplotlib, bandit, semgrep, ruff, ...
pip install -e ".[providers]"       # openai, anthropic (Ollama needs no SDK)
```

**Real energy measurement.** The sandbox runs a clean "measure" mode (no
`sys.setprofile`, which distorts energy) and wraps execution in a pluggable
`EnergyMeter`. `get_meter("auto")` picks the most credible available backend
(RAPL > CodeCarbon > powermetrics > linear proxy) and records which one was
used. Swap backends with `--energy-backend rapl` on Linux.

**Statistical rigor.** `experiments/measure.py` runs each snippet N times
(warm-ups discarded), reports mean/median/stdev/95% CI, and compares variants
with Mann-Whitney U + Cliff's delta.

**Corpus.** `corpus/build.py` loads public datasets (HumanEval/MBPP with tests,
security ground truth) and/or generates AI solutions via cached LLM providers:

```bash
python -m corpus.build --datasets security humaneval --out data/corpus/corpus.jsonl
python -m corpus.build --datasets humaneval --generate openai:gpt-4o-mini ollama:llama3.2 \
    --out data/corpus/corpus.jsonl
```

**Run the study (RQ1–RQ5).** Produces CSVs, optional matplotlib plots, and a
methods/threats note:

```bash
python -m experiments.run_study --out-dir results --runs 20 --energy-backend auto
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## FastAPI Python Sandbox (Profiler)

This repository now includes a minimal FastAPI sandbox API for dynamic analysis.

### Run locally

1. Create and activate a virtual environment.
2. Install dependencies:
   - `pip install -r sandbox/requirements.txt`
3. Start the API:
   - `uvicorn sandbox.main:app --reload`

### API endpoints

- `GET /health`
- `POST /profile`

Example request body:

```json
{
  "code": "def work(n):\n    total = 0\n    for i in range(n):\n        total += i * i\n    return total\n\nprint(work(200000))"
}
```

The response returns:
- execution success/failure
- per-function CPU time, wall time, memory delta, and estimated energy usage
- aggregated totals (CPU, wall time, peak memory, estimated energy)
- captured `stdout` and `stderr`

### Security notes

This sandbox reduces risk by running untrusted code in a separate process with strict timeout, CPU, and memory limits. It is **not** a perfect isolation boundary for hostile multi-tenant production use. For stronger isolation, run this service in container/VM isolation with seccomp/AppArmor and network egress restrictions.

---

## VS Code Extension

The `vscode-extension/` folder contains a VS Code extension that sends the active Python editor (or selection) to the security analyzer and profiling sandbox.

### Start the APIs (two terminals)

Security analyzer (port 8000):

```bash
pip install -r security/api/requirements.txt
pip install -e .
uvicorn security.api.main:app --reload --port 8000
```

The security analyzer API is **security-only** (detection) and exposes:

- `GET  /health`
- `POST /analyze` — static findings + summary

Auto-fix and cross-cutting endpoints that combine static analysis with sandbox
profiling live in the **orchestrator** API instead (run it as a separate
service):

```bash
pip install -r orchestrator/requirements.txt
pip install -e .
uvicorn orchestrator.api:app --reload --port 8002
```

- `GET  /health`
- `POST /fix` — safe auto-fixed code + applied fixes
- `POST /analyze-profile` — static analysis + dynamic profiling with performance corroboration
- `POST /compare` — auto-fix with before/after security, performance, and energy metrics

Sandbox profiler (port 8001):

```bash
pip install -r sandbox/requirements.txt
uvicorn sandbox.main:app --reload --port 8001
```

### Install and run the extension

```bash
cd vscode-extension
npm install
npm run compile
```

Open `vscode-extension/` in VS Code, press **F5** to launch an Extension Development Host, then open a Python file and run:

- **VibeGuard: Analyze File (Security + Sandbox)** — static scan + sandbox profile
- **VibeGuard: Security Scan Only** — static analysis only
- **VibeGuard: Profile in Sandbox** — runtime profile only
- **VibeGuard: Analyze Selection** — analyze the highlighted region
- **VibeGuard: Check API Health** — verify both APIs are reachable

Findings appear in the **Problems** panel; full reports appear in the **VibeGuard** output channel.

Configure API URLs under **Settings → VibeGuard** (`vibeguard.securityApiUrl`, `vibeguard.sandboxApiUrl`).

### Install permanently (production use)

Debug mode (**F5**) is only for developing the extension. To install it in VS Code or Cursor like any other extension:

**1. Build the VSIX package**

```bash
cd vscode-extension
npm install
npm run package
```

This creates `vscode-extension/vibeguard-analyzer-0.1.0.vsix`.

**2. Install in VS Code**

- Open **Extensions** (`Cmd+Shift+X`)
- Click **⋯** (top of Extensions sidebar) → **Install from VSIX…**
- Select `vibeguard-analyzer-0.1.0.vsix`

Or from a terminal:

```bash
code --install-extension vscode-extension/vibeguard-analyzer-0.1.0.vsix
```

**3. Install in Cursor**

Same UI: **Extensions → ⋯ → Install from VSIX…**, or:

```bash
cursor --install-extension vscode-extension/vibeguard-analyzer-0.1.0.vsix
```

**4. Reload the window** when prompted (`Developer: Reload Window`).

**5. Keep the backends running** — the extension is only the client. Start both APIs whenever you want to analyze (see [Start the APIs](#start-the-apis-two-terminals) above). Use **VibeGuard: Check API Health** to confirm they are up.

After install, open any Python project (not only the `vscode-extension` folder), run **Cmd+Shift+P** → **VibeGuard: Analyze File**.

To update after code changes: bump `version` in `package.json`, run `npm run package` again, and reinstall the new VSIX.

---

## Team

| Name | Institution |
|---|---|
| Haylemicheal Mekonnen | Paris Lodron University of Salzburg |
| Eslam Younis | Paris Lodron University of Salzburg |
| Elbetel Reta | Paris Lodron University of Salzburg |
