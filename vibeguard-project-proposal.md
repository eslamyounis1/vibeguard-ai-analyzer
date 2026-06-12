ASE 2026 S By Haylemicheal Mekonnen, and Eslam Younis
Paris Lodron University of Salzburg

# VibeGuard: AI Code Quality, Energy, and Security

# Analyzer

## Overview

The rise of AI-assisted programming (e.g., GitHub Copilot and Claude) has enabled rapid “vibe coding,”
where developers generate code quickly with minimal manual effort. While effective, such code often
suffers from poor structure, inefficiency, and security and privacy vulnerabilities.
VibeGuard is a system that analyzes AI-generated code to ensure it is clean, efficient, and secure. It
combines static code analysis with runtime profiling to detect issues and provide actionable improvements
or automatic fixes.

## Objectives

```
● Detect and classify code smells in AI-generated code
● Analyze energy consumption and performance bottlenecks
● Identify security and privacy risks
● Provide automated suggestions or refactored code
● Improve overall code quality, efficiency, and reliability
```
## System Architecture

```
● Input Layer
○ Accepts source code
● Static Analysis Layer
○ Parses code into an Abstract Syntax Tree (AST)
○ Detects code smells and security vulnerabilities
● Dynamic Analysis Layer
○ Executes code in a controlled sandbox
○ Profiles CPU, memory, and execution time
○ Estimates energy consumption
● Optimization Layer
○ Applies rule-based and AI-assisted improvements
○ Validates optimizations using profiling results
● Output Layer
○ Generates reports and optimized code
```

## Key Components

```
● Code Smell Detector
○ Identifies inefficient or poorly structured patterns such as redundant loops, duplicated
logic, unused variables, and overly complex constructs.
● Energy Efficiency Analyzer
○ Measures execution time, CPU usage, and memory consumption to estimate energy usage
and detect performance hotspots.
● Security & Privacy Analyzer
○ Detects vulnerabilities such as unsafe input handling, hardcoded secrets, insecure API
usage, and risky functions (e.g., eval).
● Profiling Engine
○ Uses runtime profilers to identify bottlenecks and validate performance issues detected
during static analysis.
● Suggestion & Auto-Fix Engine
○ Generates optimized code and explanations, with the option to automatically refactor
inefficient or unsafe code.
```
## Expected Output

```
● Analysis Report
○ Detected code smells
○ Energy and performance metrics
○ Security and privacy issues
● Optimization Suggestions
○ Clear recommendations with explanations
● Refactored Code
○ Improved version of the original code
● Comparative Metrics
○ Before vs. after performance and energy usage
```

