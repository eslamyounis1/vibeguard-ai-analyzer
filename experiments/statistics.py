"""Statistical helpers used by the publication experiments."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from statistics import NormalDist
from typing import Callable, Sequence


@dataclass(frozen=True)
class BinaryMetrics:
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def specificity(self) -> float:
        return self.tn / (self.tn + self.fp) if self.tn + self.fp else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "specificity": round(self.specificity, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
        }


def binary_metrics(labels: Sequence[bool], predictions: Sequence[bool]) -> BinaryMetrics:
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must have equal length")
    tp = fp = tn = fn = 0
    for label, prediction in zip(labels, predictions):
        if label and prediction:
            tp += 1
        elif not label and prediction:
            fp += 1
        elif not label and not prediction:
            tn += 1
        else:
            fn += 1
    return BinaryMetrics(tp=tp, fp=fp, tn=tn, fn=fn)


def wilson_interval(successes: int, total: int, confidence: float = 0.95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if total <= 0 or not 0 <= successes <= total:
        raise ValueError("Expected total > 0 and 0 <= successes <= total")
    z = NormalDist().inv_cdf(0.5 + confidence / 2)
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)


def bootstrap_interval(
    values: Sequence,
    statistic: Callable[[Sequence], float],
    *,
    confidence: float = 0.95,
    iterations: int = 5000,
    seed: int = 20260613,
) -> tuple[float, float]:
    """Deterministic percentile bootstrap interval."""
    if not values:
        raise ValueError("values must not be empty")
    rng = random.Random(seed)
    n = len(values)
    estimates = []
    for _ in range(iterations):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        estimates.append(float(statistic(sample)))
    estimates.sort()
    tail = (1 - confidence) / 2
    low = estimates[max(0, int(tail * iterations))]
    high = estimates[min(iterations - 1, int((1 - tail) * iterations) - 1)]
    return low, high


def paired_bootstrap_metric_difference(
    labels: Sequence[bool],
    first: Sequence[bool],
    second: Sequence[bool],
    *,
    metric: str = "f1",
    confidence: float = 0.95,
    iterations: int = 5000,
    seed: int = 20260613,
) -> tuple[float, float]:
    """CI for first-minus-second on a paired binary metric."""
    if not (len(labels) == len(first) == len(second)):
        raise ValueError("paired inputs must have equal length")
    rows = list(zip(labels, first, second))

    def _difference(sample: Sequence[tuple[bool, bool, bool]]) -> float:
        ys = [row[0] for row in sample]
        a = binary_metrics(ys, [row[1] for row in sample])
        b = binary_metrics(ys, [row[2] for row in sample])
        return float(getattr(a, metric) - getattr(b, metric))

    return bootstrap_interval(
        rows,
        _difference,
        confidence=confidence,
        iterations=iterations,
        seed=seed,
    )


def clustered_paired_bootstrap_metric_difference(
    task_ids: Sequence[str],
    labels: Sequence[bool],
    first: Sequence[bool],
    second: Sequence[bool],
    *,
    metric: str = "f1",
    confidence: float = 0.95,
    iterations: int = 5000,
    seed: int = 20260613,
) -> tuple[float, float]:
    """Task-cluster bootstrap CI for a paired first-minus-second metric."""
    if not (len(task_ids) == len(labels) == len(first) == len(second)):
        raise ValueError("clustered paired inputs must have equal length")
    clusters: dict[str, list[tuple[bool, bool, bool]]] = {}
    for task_id, label, a_pred, b_pred in zip(task_ids, labels, first, second):
        clusters.setdefault(str(task_id), []).append((label, a_pred, b_pred))

    def _difference(sample: Sequence[list[tuple[bool, bool, bool]]]) -> float:
        rows = [row for cluster in sample for row in cluster]
        ys = [row[0] for row in rows]
        first_metrics = binary_metrics(ys, [row[1] for row in rows])
        second_metrics = binary_metrics(ys, [row[2] for row in rows])
        return float(
            getattr(first_metrics, metric) - getattr(second_metrics, metric)
        )

    return bootstrap_interval(
        list(clusters.values()),
        _difference,
        confidence=confidence,
        iterations=iterations,
        seed=seed,
    )


def auroc(labels: Sequence[bool], scores: Sequence[float]) -> float:
    """Area under the ROC curve using average ranks for tied scores."""
    if len(labels) != len(scores):
        raise ValueError("labels and scores must have equal length")
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        raise ValueError("AUROC requires both positive and negative labels")
    from scipy.stats import rankdata

    ranks = rankdata(scores, method="average")
    positive_rank_sum = sum(rank for rank, label in zip(ranks, labels) if label)
    return float(
        (positive_rank_sum - positives * (positives + 1) / 2)
        / (positives * negatives)
    )


def mcnemar_exact(first_correct: Sequence[bool], second_correct: Sequence[bool]) -> dict:
    """Exact two-sided McNemar test for paired correctness outcomes."""
    if len(first_correct) != len(second_correct):
        raise ValueError("paired inputs must have equal length")
    first_only = sum(a and not b for a, b in zip(first_correct, second_correct))
    second_only = sum(b and not a for a, b in zip(first_correct, second_correct))
    discordant = first_only + second_only
    if discordant == 0:
        p_value = 1.0
    else:
        from scipy.stats import binomtest

        p_value = float(binomtest(min(first_only, second_only), discordant, 0.5).pvalue)
    return {
        "first_only_correct": first_only,
        "second_only_correct": second_only,
        "discordant": discordant,
        "p_value": p_value,
    }
