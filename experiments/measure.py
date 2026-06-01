"""Statistical energy/time measurement harness.

Runs a code snippet many times in the sandbox (discarding warm-ups), summarizes
each metric with mean/median/stdev/95% CI, and compares two variants with a
non-parametric test (Mann-Whitney U) plus an effect size (Cliff's delta). This
is what turns raw sandbox numbers into defensible, paper-ready measurements.

No hard dependency on SciPy: statistics are implemented here, and SciPy is used
only if installed (for a more exact Mann-Whitney p-value).
"""

from __future__ import annotations

import math
import os
import platform
import shutil
import statistics
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from sandbox.profiler import measure_code

_METRICS = (
    "energy_joules_estimate",
    "wall_time_seconds",
    "cpu_time_seconds",
    "memory_peak_bytes",
)


@dataclass
class TrialStats:
    metric: str
    n: int
    mean: float
    median: float
    stdev: float
    ci95_low: float
    ci95_high: float
    raw: List[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def summarize(metric: str, values: List[float]) -> TrialStats:
    n = len(values)
    if n == 0:
        return TrialStats(metric, 0, 0.0, 0.0, 0.0, 0.0, 0.0, [])
    mean = statistics.fmean(values)
    median = statistics.median(values)
    stdev = statistics.stdev(values) if n > 1 else 0.0
    # 95% CI of the mean via normal approximation (1.96 * SE).
    half = 1.96 * (stdev / math.sqrt(n)) if n > 1 else 0.0
    return TrialStats(
        metric=metric,
        n=n,
        mean=round(mean, 6),
        median=round(median, 6),
        stdev=round(stdev, 6),
        ci95_low=round(mean - half, 6),
        ci95_high=round(mean + half, 6),
        raw=values,
    )


@dataclass
class MeasurementResult:
    runs: int
    warmup: int
    backend: Optional[str]
    environment: dict
    stats: Dict[str, TrialStats]
    samples: Dict[str, List[float]]
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "runs": self.runs,
            "warmup": self.warmup,
            "backend": self.backend,
            "environment": self.environment,
            "stats": {k: v.to_dict() for k, v in self.stats.items()},
            "samples": self.samples,
            "errors": self.errors,
        }


def environment_metadata() -> dict:
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "processor": platform.processor() or platform.machine(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "taskset_available": shutil.which("taskset") is not None,
        "note": "Pin cores (taskset/cpuset) and disable turbo for publication-quality runs.",
    }


def measure_repeated(
    code: str,
    runs: int = 20,
    warmup: int = 3,
    energy_backend: str = "auto",
    cpu_seconds: int = 10,
    memory_mb: int = 512,
) -> MeasurementResult:
    """Execute ``code`` ``warmup + runs`` times; keep the last ``runs`` samples."""
    samples: Dict[str, List[float]] = {m: [] for m in _METRICS}
    errors: List[str] = []
    backend: Optional[str] = None

    for i in range(warmup + runs):
        result = measure_code(code, energy_backend=energy_backend, cpu_seconds=cpu_seconds, memory_mb=memory_mb)
        if not result.get("ok"):
            errors.append(result.get("error_message") or result.get("error_type") or "unknown error")
            continue
        if i < warmup:
            continue
        totals = result.get("totals") or {}
        backend = totals.get("energy_backend", backend)
        for metric in _METRICS:
            value = totals.get(metric)
            if value is not None:
                samples[metric].append(float(value))

    stats = {metric: summarize(metric, values) for metric, values in samples.items() if values}
    return MeasurementResult(
        runs=runs,
        warmup=warmup,
        backend=backend,
        environment=environment_metadata(),
        stats=stats,
        samples=samples,
        errors=errors,
    )


def cliffs_delta(a: List[float], b: List[float]) -> tuple[float, str]:
    """Cliff's delta effect size and its magnitude label."""
    if not a or not b:
        return 0.0, "undefined"
    greater = sum(1 for x in a for y in b if x > y)
    less = sum(1 for x in a for y in b if x < y)
    delta = (greater - less) / (len(a) * len(b))
    magnitude = abs(delta)
    if magnitude < 0.147:
        label = "negligible"
    elif magnitude < 0.33:
        label = "small"
    elif magnitude < 0.474:
        label = "medium"
    else:
        label = "large"
    return round(delta, 4), label


def _mannwhitney_u(a: List[float], b: List[float]) -> tuple[float, float]:
    """Mann-Whitney U statistic and two-sided p-value (normal approximation).

    Uses SciPy when available for a more exact p-value; otherwise falls back to
    a tie-corrected normal approximation.
    """
    try:
        from scipy.stats import mannwhitneyu

        stat, p = mannwhitneyu(a, b, alternative="two-sided")
        return float(stat), float(p)
    except Exception:
        pass

    na, nb = len(a), len(b)
    if na == 0 or nb == 0:
        return 0.0, 1.0
    combined = sorted([(v, "a") for v in a] + [(v, "b") for v in b], key=lambda t: t[0])
    # Average ranks (handle ties).
    ranks = [0.0] * len(combined)
    i = 0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg_rank
        i = j + 1
    rank_a = sum(ranks[idx] for idx, (_, label) in enumerate(combined) if label == "a")
    u_a = rank_a - na * (na + 1) / 2.0
    u = min(u_a, na * nb - u_a)
    mu = na * nb / 2.0
    sigma = math.sqrt(na * nb * (na + nb + 1) / 12.0)
    if sigma == 0:
        return u, 1.0
    z = (u - mu) / sigma
    p = 2.0 * (1.0 - _normal_cdf(abs(z)))
    return u, round(min(1.0, max(0.0, p)), 6)


def _normal_cdf(x: float) -> float:
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


@dataclass
class Comparison:
    metric: str
    baseline: TrialStats
    candidate: TrialStats
    improvement_pct: Optional[float]
    cliffs_delta: float
    effect_size: str
    mannwhitney_u: float
    p_value: float
    significant: bool

    def to_dict(self) -> dict:
        d = asdict(self)
        d["baseline"] = self.baseline.to_dict()
        d["candidate"] = self.candidate.to_dict()
        return d


def compare_metric(metric: str, baseline: List[float], candidate: List[float], alpha: float = 0.05) -> Comparison:
    base_stats = summarize(metric, baseline)
    cand_stats = summarize(metric, candidate)
    delta, label = cliffs_delta(baseline, candidate)
    u, p = _mannwhitney_u(baseline, candidate)
    improvement = None
    if base_stats.mean:
        improvement = round((base_stats.mean - cand_stats.mean) / base_stats.mean * 100.0, 2)
    return Comparison(
        metric=metric,
        baseline=base_stats,
        candidate=cand_stats,
        improvement_pct=improvement,
        cliffs_delta=delta,
        effect_size=label,
        mannwhitney_u=u,
        p_value=p,
        significant=p < alpha,
    )


def compare_variants(
    baseline_code: str,
    candidate_code: str,
    runs: int = 20,
    warmup: int = 3,
    energy_backend: str = "auto",
) -> Dict[str, Comparison]:
    """Measure two code variants and compare each metric statistically."""
    base = measure_repeated(baseline_code, runs=runs, warmup=warmup, energy_backend=energy_backend)
    cand = measure_repeated(candidate_code, runs=runs, warmup=warmup, energy_backend=energy_backend)
    comparisons: Dict[str, Comparison] = {}
    for metric in _METRICS:
        if base.samples.get(metric) and cand.samples.get(metric):
            comparisons[metric] = compare_metric(metric, base.samples[metric], cand.samples[metric])
    return comparisons
