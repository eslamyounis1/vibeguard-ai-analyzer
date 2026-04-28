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

VibeGuard is currently in an **early but working stage**.

**What is available now:**
- Security scanning for Python projects (static analysis)
- Runtime profiling through a sandbox API (time, memory, estimated energy)
- Benchmarking tools to measure detection quality

**What comes next:**
- Broader code-quality analysis
- Automated optimization and repair suggestions
- End-to-end reporting across quality, efficiency, and security

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
| VG001 | Use of `eval()` | HIGH |
| VG002 | Use of `exec()` | HIGH |
| VG003 | Hardcoded Secret | HIGH |
| VG004 | Insecure Randomness | MEDIUM |
| VG005 | Dangerous Subprocess Usage (`shell=True`) | HIGH |
| VG006 | Pickle Deserialization | HIGH |
| VG007 | Assert Used for Security Check | MEDIUM |

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
vibeguard/
├── cli/            Command-line interface
├── core/           Scanner orchestration
├── analyzers/
│   └── security/   Security analyzer (Phase 1)
├── rules/
│   └── security/   Security rules VG001–VG007
├── models/         Finding and ScanResult data models
├── reporters/      Text and JSON output formatters
└── utils/          File traversal helpers
```

Future analyzers (quality, performance, energy) plug in as siblings under `analyzers/` and `rules/`.

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

## Team

| Name | Institution |
|---|---|
| Haylemicheal Mekonnen | Paris Lodron University of Salzburg |
| Eslam Younis | Paris Lodron University of Salzburg |
| Elbetel Reta | Paris Lodron University of Salzburg |
