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

> **TBD** — to be updated by the team.

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
