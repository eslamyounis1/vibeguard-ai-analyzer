"""Novel security metrics for LLM code generation evaluation.

Implements pass@k-style estimators for security properties:
- vulnerable@k  — probability ≥1 of k samples is vulnerable
- secure@k       — probability ≥1 of k samples is both functional AND secure
- fix_rate@k     — probability auto-fix produces a secure solution in k attempts

All estimators use the unbiased combinatorial formula from Chen et al. 2021
(Codex/HumanEval): pass@k = 1 - C(n-c, k) / C(n, k).
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, List, Optional, Sequence


# ---------------------------------------------------------------------------
# Core estimator
# ---------------------------------------------------------------------------

def _at_k(n: int, c: int, k: int) -> float:
    """Probability that at least 1 of k draws (without replacement) is a 'success'.

    Uses the unbiased estimator: 1 - prod_{i=0}^{k-1} (n-c-i)/(n-i).
    Equivalent to 1 - C(n-c, k) / C(n, k).

    Args:
        n: Total number of samples.
        c: Number of 'success' samples.
        k: Number of draws.

    Returns:
        Probability in [0.0, 1.0].
    """
    if n < 0 or c < 0 or c > n:
        raise ValueError(f"Expected 0 <= c <= n, got n={n}, c={c}")
    if k < 1:
        raise ValueError(f"k must be positive, got {k}")
    if n < k:
        raise ValueError(f"pass@k is undefined when k > n (k={k}, n={n})")
    if c == 0:
        return 0.0
    if c >= n:
        return 1.0
    if n - c < k:
        return 1.0
    return 1.0 - math.comb(n - c, k) / math.comb(n, k)


# ---------------------------------------------------------------------------
# Public metric functions
# ---------------------------------------------------------------------------

def vulnerable_at_k(n: int, c_vuln: int, k: int) -> float:
    """Probability that at least 1 of k samples is vulnerable.

    Args:
        n: Total samples for this task/model combination.
        c_vuln: Number of vulnerable samples.
        k: Number of draws.
    """
    return _at_k(n, c_vuln, k)


def secure_at_k(n: int, c_secure: int, k: int) -> float:
    """Probability that at least 1 of k samples is both functional AND secure.

    Args:
        n: Total samples.
        c_secure: Samples that pass both functional tests and have no security findings.
        k: Number of draws.
    """
    return _at_k(n, c_secure, k)


def fix_rate_at_k(n: int, c_fixed: int, k: int) -> float:
    """Probability that auto-fix produces a secure solution in k fix attempts.

    Args:
        n: Total vulnerable samples.
        c_fixed: Samples where auto-fix removed all security findings.
        k: Number of fix attempts.
    """
    return _at_k(n, c_fixed, k)


# ---------------------------------------------------------------------------
# Aggregate helpers
# ---------------------------------------------------------------------------

def compute_metrics_for_group(
    samples: Sequence[dict],
    k_values: Sequence[int] = (1, 5, 10),
    vuln_key: str = "has_finding",
    secure_key: str = "is_secure",
    fixed_key: Optional[str] = None,
) -> Dict[str, float]:
    """Compute vulnerable@k and secure@k for a group of samples.

    Args:
        samples: List of dicts with boolean fields.
        k_values: k values to compute.
        vuln_key: Dict key that is True when sample is vulnerable.
        secure_key: Dict key that is True when sample is functional+secure.
        fixed_key: If set, also compute fix_rate@k.

    Returns:
        Dict with keys like "vulnerable@1", "secure@5", "fix_rate@10".
    """
    n = len(samples)
    c_vuln = sum(1 for s in samples if s.get(vuln_key))
    c_secure = sum(1 for s in samples if s.get(secure_key))
    c_fixed = sum(1 for s in samples if s.get(fixed_key)) if fixed_key else 0

    result: Dict[str, float] = {}
    for k in k_values:
        if k > n:
            continue
        result[f"vulnerable@{k}"] = round(vulnerable_at_k(n, c_vuln, k), 4)
        result[f"secure@{k}"] = round(secure_at_k(n, c_secure, k), 4)
        if fixed_key is not None:
            result[f"fix_rate@{k}"] = round(fix_rate_at_k(n, c_fixed, k), 4)
    result["n"] = n
    result["c_vuln"] = c_vuln
    result["c_secure"] = c_secure
    if fixed_key is not None:
        result["c_fixed"] = c_fixed
    return result


def compute_task_level_at_k(
    samples: Sequence[dict],
    *,
    task_key: str = "task_id",
    success_key: str,
    k_values: Sequence[int] = (1, 3, 5),
) -> Dict[str, float]:
    """Compute pass@k per task and macro-average across tasks.

    Each task must have repeated, exchangeable samples. Pooling different tasks
    before applying the combinatorial estimator is invalid because it treats
    samples from unrelated tasks as alternative attempts at the same problem.
    """
    by_task: Dict[str, list[dict]] = defaultdict(list)
    for sample in samples:
        by_task[str(sample[task_key])].append(sample)

    result: Dict[str, float] = {"tasks": len(by_task)}
    if not by_task:
        return result

    result["min_samples_per_task"] = min(len(group) for group in by_task.values())
    result["max_samples_per_task"] = max(len(group) for group in by_task.values())
    for k in k_values:
        estimates = []
        for group in by_task.values():
            n = len(group)
            if n < k:
                continue
            c = sum(1 for sample in group if bool(sample.get(success_key)))
            estimates.append(_at_k(n, c, k))
        if estimates:
            result[f"{success_key}@{k}"] = round(sum(estimates) / len(estimates), 4)
            result[f"{success_key}@{k}_tasks"] = len(estimates)
    return result


def compute_metrics_per_model(
    rows: List[dict],
    model_key: str = "source",
    k_values: Sequence[int] = (1, 5, 10),
    vuln_key: str = "has_finding",
    secure_key: str = "is_secure",
    fixed_key: Optional[str] = None,
) -> List[dict]:
    """Group rows by model and compute metrics for each group.

    Returns a list of dicts ready for CSV writing.
    """
    from collections import defaultdict
    groups: Dict[str, list] = defaultdict(list)
    for row in rows:
        groups[row[model_key]].append(row)

    results = []
    for model, group in sorted(groups.items()):
        metrics = compute_metrics_for_group(group, k_values, vuln_key, secure_key, fixed_key)
        metrics[model_key] = model
        results.append(metrics)
    return results
