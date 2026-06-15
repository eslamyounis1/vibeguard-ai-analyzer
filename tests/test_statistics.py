import pytest

from corpus.schema import CorpusSample
from experiments.baselines import ToolRun
from experiments.run_research_evaluation import _cross_dataset_rows
from experiments.statistics import (
    auroc,
    binary_metrics,
    clustered_paired_bootstrap_metric_difference,
    mcnemar_exact,
    paired_bootstrap_metric_difference,
    wilson_interval,
)


def test_binary_metrics():
    result = binary_metrics([True, True, False, False], [True, False, True, False])
    assert result.to_dict()["tp"] == 1
    assert result.to_dict()["fp"] == 1
    assert result.f1 == pytest.approx(0.5)


def test_wilson_interval_contains_observed_rate():
    low, high = wilson_interval(7, 10)
    assert low < 0.7 < high


def test_mcnemar_exact_counts_discordant_pairs():
    result = mcnemar_exact([True, True, False], [False, True, True])
    assert result["first_only_correct"] == 1
    assert result["second_only_correct"] == 1
    assert result["p_value"] == 1.0


def test_paired_bootstrap_difference_is_reproducible():
    labels = [True, True, False, False] * 4
    first = [True, True, False, False] * 4
    second = [True, False, True, False] * 4
    assert paired_bootstrap_metric_difference(labels, first, second, iterations=100) == (
        paired_bootstrap_metric_difference(labels, first, second, iterations=100)
    )


def test_clustered_paired_bootstrap_is_reproducible():
    task_ids = ["a", "a", "b", "b"]
    labels = [True, False, True, False]
    first = [True, False, True, False]
    second = [False, False, False, False]
    assert clustered_paired_bootstrap_metric_difference(
        task_ids, labels, first, second, iterations=100
    ) == clustered_paired_bootstrap_metric_difference(
        task_ids, labels, first, second, iterations=100
    )


def test_auroc_with_ties():
    assert auroc([False, False, True, True], [0.0, 0.5, 0.5, 1.0]) == 0.875


def test_cross_dataset_evaluation_rejects_failed_tool_runs():
    sample = CorpusSample(
        id="sample",
        task_id="task",
        source="test",
        prompt="",
        code="x = 1",
    )

    with pytest.raises(RuntimeError, match="tool failed on dataset"):
        _cross_dataset_rows(
            {"dataset": [sample]},
            {
                "tool": lambda samples: {
                    "sample": ToolRun("tool", ok=False, error="not installed")
                }
            },
        )
