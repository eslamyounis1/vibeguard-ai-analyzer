"""Run the publication evaluation and emit auditable tabular artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
import subprocess
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Callable, Iterable, Sequence

from corpus.loaders import load_evalplus, load_sallm, load_securityeval
from corpus.schema import CorpusSample, read_corpus
from experiments.baselines import ToolRun
from experiments.batch_tools import (
    run_bandit_batch,
    run_semgrep_batch,
    run_vibeguard_batch,
)
from experiments.cwe_families import cwe_to_family
from experiments.metrics import secure_at_k
from experiments.statistics import (
    auroc,
    binary_metrics,
    bootstrap_interval,
    clustered_paired_bootstrap_metric_difference,
    mcnemar_exact,
    wilson_interval,
)


def _write_csv(path: Path, rows: Sequence[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _round_interval(interval: tuple[float, float]) -> list[float]:
    return [round(interval[0], 4), round(interval[1], 4)]


def _target_cwe(sample: CorpusSample) -> str | None:
    value = (
        sample.expected_security_labels[0]
        if sample.expected_security_labels
        else (sample.metadata or {}).get("cwe")
    )
    if not value:
        return None
    prefix, _, number = str(value).partition("-")
    return f"CWE-{int(number)}" if prefix.upper() == "CWE" and number.isdigit() else str(value)


def _security_findings(run: ToolRun):
    return [finding for finding in run.findings if finding.category == "security"]


def _exact_prediction(run: ToolRun, target: str | None) -> bool:
    return bool(target and target in {finding.cwe for finding in _security_findings(run)})


def _family_prediction(run: ToolRun, target: str | None) -> bool:
    if not target:
        return False
    family = cwe_to_family(target)
    return any(
        finding.cwe and cwe_to_family(finding.cwe) == family
        for finding in _security_findings(run)
    )


def _confirmed_prediction(run: ToolRun, target: str | None) -> bool:
    statuses = getattr(run, "dynamic_statuses", {})
    return bool(target and "confirmed" in statuses.get(target, set()))


def _confirmed_family_prediction(run: ToolRun, target: str | None) -> bool:
    if not target:
        return False
    target_family = cwe_to_family(target)
    statuses = getattr(run, "dynamic_statuses", {})
    return any(
        "confirmed" in cwe_statuses and cwe_to_family(cwe) == target_family
        for cwe, cwe_statuses in statuses.items()
    )


def _cluster_metric_interval(
    rows: Sequence[dict],
    prediction_key: str,
    metric: str,
    iterations: int,
) -> tuple[float, float]:
    clusters: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        clusters[row["task_id"]].append(row)

    def statistic(sample: Sequence[list[dict]]) -> float:
        flat = [row for cluster in sample for row in cluster]
        result = binary_metrics(
            [bool(row["oracle_insecure"]) for row in flat],
            [bool(row[prediction_key]) for row in flat],
        )
        return float(getattr(result, metric))

    return bootstrap_interval(
        list(clusters.values()), statistic, iterations=iterations
    )


def _detection_metric_row(
    rows: Sequence[dict],
    *,
    tool: str,
    endpoint: str,
    prediction_key: str,
    iterations: int,
) -> dict:
    labels = [bool(row["oracle_insecure"]) for row in rows]
    predictions = [bool(row[prediction_key]) for row in rows]
    metrics = binary_metrics(labels, predictions)
    result = {
        "tool": tool,
        "endpoint": endpoint,
        "n": len(rows),
        **metrics.to_dict(),
    }
    precision_n = metrics.tp + metrics.fp
    recall_n = metrics.tp + metrics.fn
    specificity_n = metrics.tn + metrics.fp
    if precision_n:
        result["precision_ci95"] = json.dumps(
            _round_interval(wilson_interval(metrics.tp, precision_n))
        )
    if recall_n:
        result["recall_ci95"] = json.dumps(
            _round_interval(wilson_interval(metrics.tp, recall_n))
        )
    if specificity_n:
        result["specificity_ci95"] = json.dumps(
            _round_interval(wilson_interval(metrics.tn, specificity_n))
        )
    result["f1_cluster_ci95"] = json.dumps(
        _round_interval(
            _cluster_metric_interval(rows, prediction_key, "f1", iterations)
        )
    )
    for metric_name in ("precision", "recall", "specificity"):
        result[f"{metric_name}_cluster_ci95"] = json.dumps(
            _round_interval(
                _cluster_metric_interval(
                    rows, prediction_key, metric_name, iterations
                )
            )
        )
    return result


def _task_rate_summary(
    rows: Sequence[dict], key: str, iterations: int
) -> tuple[float, tuple[float, float]]:
    by_task: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_task[row["task_id"]].append(row)
    rates = [mean(bool(row[key]) for row in group) for group in by_task.values()]
    return mean(rates), bootstrap_interval(
        rates, lambda values: mean(values), iterations=iterations
    )


def _model_outcomes(rows: Sequence[dict], iterations: int) -> list[dict]:
    by_source: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_source[row["source"]].append(row)
    output = []
    for source, group in sorted(by_source.items()):
        result = {
            "source": source,
            "n": len(group),
            "tasks": len({row["task_id"] for row in group}),
        }
        for key in (
            "functional",
            "oracle_secure",
            "functional_and_secure",
            "functional_but_insecure",
        ):
            rate, interval = _task_rate_summary(group, key, iterations)
            result[f"{key}_rate"] = round(rate, 4)
            result[f"{key}_cluster_ci95"] = json.dumps(_round_interval(interval))
        output.append(result)
    return output


def _at_k_rows(rows: Sequence[dict], iterations: int) -> list[dict]:
    by_source: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        if row["source"] != "human":
            by_source[row["source"]].append(row)
    output = []
    endpoints = {
        "functional": "functional",
        "secure": "functional_and_secure",
        "vulnerable": "functional_but_insecure",
    }
    for source, source_rows in sorted(by_source.items()):
        by_task: dict[str, list[dict]] = defaultdict(list)
        for row in source_rows:
            by_task[row["task_id"]].append(row)
        for endpoint, key in endpoints.items():
            for k in (1, 3, 5):
                estimates = []
                for group in by_task.values():
                    if len(group) < k:
                        continue
                    successes = sum(bool(row[key]) for row in group)
                    estimates.append(secure_at_k(len(group), successes, k))
                if not estimates:
                    continue
                interval = bootstrap_interval(
                    estimates, lambda values: mean(values), iterations=iterations
                )
                output.append({
                    "source": source,
                    "endpoint": endpoint,
                    "k": k,
                    "tasks": len(estimates),
                    "estimate": round(mean(estimates), 4),
                    "cluster_ci95": json.dumps(_round_interval(interval)),
                })
    return output


def _prevalence_rows(
    samples: Sequence[CorpusSample], runs: dict[str, ToolRun]
) -> list[dict]:
    by_source: dict[str, list[CorpusSample]] = defaultdict(list)
    for sample in samples:
        by_source[sample.source].append(sample)
    output = []
    for source, group in sorted(by_source.items()):
        counts = {"security": [], "code_smell": [], "performance": [], "total": []}
        for sample in group:
            run = runs[sample.id]
            sample_counts = {
                category: sum(f.category == category for f in run.findings)
                for category in ("security", "code_smell", "performance")
            }
            for category, count in sample_counts.items():
                counts[category].append(count)
            counts["total"].append(len(run.findings))
        output.append({
            "source": source,
            "n": len(group),
            "mean_security": round(mean(counts["security"]), 4),
            "mean_code_smell": round(mean(counts["code_smell"]), 4),
            "mean_performance": round(mean(counts["performance"]), 4),
            "mean_total": round(mean(counts["total"]), 4),
            "any_finding_rate": round(mean(value > 0 for value in counts["total"]), 4),
        })
    return output


def _rate_row(
    dataset: str,
    tool: str,
    endpoint: str,
    successes: int,
    total: int,
) -> dict:
    interval = wilson_interval(successes, total)
    return {
        "dataset": dataset,
        "tool": tool,
        "endpoint": endpoint,
        "successes": successes,
        "n": total,
        "rate": round(successes / total, 4),
        "ci95": json.dumps(_round_interval(interval)),
    }


def _cross_dataset_rows(
    datasets: dict[str, list[CorpusSample]],
    tool_runners: dict[str, Callable[[Iterable[CorpusSample]], dict[str, ToolRun]]],
) -> tuple[list[dict], dict[str, dict[str, ToolRun]]]:
    rows = []
    all_runs: dict[str, dict[str, ToolRun]] = {}
    for dataset, samples in datasets.items():
        for tool, runner in tool_runners.items():
            print(f"Running {tool} on {dataset} ({len(samples)} samples)", flush=True)
            runs = runner(samples)
            _require_successful_runs(dataset, tool, samples, runs)
            all_runs[f"{dataset}:{tool}"] = runs
            any_alerts = sum(bool(_security_findings(runs[sample.id])) for sample in samples)
            rows.append(_rate_row(dataset, tool, "any_security_alert", any_alerts, len(samples)))
            labeled = [sample for sample in samples if _target_cwe(sample)]
            if not labeled:
                continue
            exact = sum(
                _exact_prediction(runs[sample.id], _target_cwe(sample))
                for sample in labeled
            )
            family = sum(
                _family_prediction(runs[sample.id], _target_cwe(sample))
                for sample in labeled
            )
            rows.append(_rate_row(dataset, tool, "target_cwe_recall", exact, len(labeled)))
            rows.append(_rate_row(dataset, tool, "target_family_recall", family, len(labeled)))
    return rows, all_runs


def _require_successful_runs(
    dataset: str,
    tool: str,
    samples: Sequence[CorpusSample],
    runs: dict[str, ToolRun],
) -> None:
    missing = [sample.id for sample in samples if sample.id not in runs]
    failures = [
        runs[sample.id]
        for sample in samples
        if sample.id in runs and not runs[sample.id].ok
    ]
    if not missing and not failures:
        return

    details = []
    if missing:
        details.append(f"{len(missing)} missing results")
    if failures:
        first_error = failures[0].error or "unknown error"
        details.append(f"{len(failures)} failed results; first error: {first_error}")
    raise RuntimeError(f"{tool} failed on {dataset}: {'; '.join(details)}")


def _command_output(command: list[str], cwd: Path | None = None) -> str | None:
    try:
        result = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, check=False
        )
        return result.stdout.strip() or None
    except OSError:
        return None


def _source_tree_sha256() -> str:
    digest = hashlib.sha256()
    roots = ["corpus", "experiments", "fixers", "sandbox", "security", "scripts"]
    paths = [Path("pyproject.toml"), Path("requirements-research.txt")]
    for root in roots:
        paths.extend(
            path for path in Path(root).rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        )
    for path in sorted(paths):
        digest.update(str(path).encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _manifest(corpus_path: Path) -> dict:
    packages = {}
    for package in ("vibeguard", "bandit", "semgrep", "scipy", "pandas", "openai"):
        try:
            packages[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            packages[package] = None
    datasets = {}
    for name in ("cweval", "sallm", "securityeval", "semgrep-rules"):
        path = Path("dataset") / name
        datasets[name] = _command_output(["git", "rev-parse", "HEAD"], path)
    return {
        "repository_commit": _command_output(["git", "rev-parse", "HEAD"]),
        "repository_dirty": bool(_command_output(["git", "status", "--short"])),
        "source_tree_sha256": _source_tree_sha256(),
        "corpus": str(corpus_path),
        "corpus_sha256": hashlib.sha256(corpus_path.read_bytes()).hexdigest(),
        "packages": packages,
        "dataset_commits": datasets,
    }


def run_evaluation(
    corpus_path: str | Path,
    out_dir: str | Path,
    *,
    evalplus_path: str | Path,
    bootstrap_iterations: int = 5000,
) -> dict:
    corpus_path = Path(corpus_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    samples = read_corpus(corpus_path)
    oracle_samples = [
        sample for sample in samples
        if isinstance((sample.metadata or {}).get("oracle", {}).get("secure"), bool)
    ]
    excluded_samples = [
        sample for sample in samples
        if not isinstance((sample.metadata or {}).get("oracle", {}).get("secure"), bool)
    ]
    if not oracle_samples:
        raise ValueError("Corpus has no sample-level oracle annotations")

    exclusion_rows = []
    for sample in excluded_samples:
        oracle = (sample.metadata or {}).get("oracle", {})
        exclusion_rows.append({
            "id": sample.id,
            "task_id": sample.task_id,
            "source": sample.source,
            "functional": oracle.get("functional"),
            "secure": oracle.get("secure"),
            "error": oracle.get("error") or "oracle outcome unavailable",
        })
    _write_csv(out_dir / "cweval_oracle_exclusions.csv", exclusion_rows)

    print(f"Running VibeGuard ablations on {len(oracle_samples)} CWEval samples", flush=True)
    no_taint_runs = run_vibeguard_batch(oracle_samples, enable_taint=False)
    vibeguard_runs = run_vibeguard_batch(oracle_samples, enable_taint=True)
    dynamic_runs = run_vibeguard_batch(
        oracle_samples, enable_taint=True, dynamic_verify=True
    )
    print("Running Bandit on CWEval", flush=True)
    bandit_runs = run_bandit_batch(oracle_samples)
    print("Running Semgrep on CWEval", flush=True)
    semgrep_runs = run_semgrep_batch(oracle_samples)
    tools = {
        "vibeguard_no_taint": no_taint_runs,
        "vibeguard": vibeguard_runs,
        "vibeguard_confirmed": dynamic_runs,
        "bandit": bandit_runs,
        "semgrep": semgrep_runs,
    }
    for tool, runs in tools.items():
        _require_successful_runs("cweval", tool, oracle_samples, runs)

    sample_rows = []
    for sample in oracle_samples:
        oracle = sample.metadata["oracle"]
        target = _target_cwe(sample)
        row = {
            "id": sample.id,
            "task_id": sample.task_id,
            "source": sample.source,
            "sample_index": (sample.metadata or {}).get("sample_index"),
            "target_cwe": target,
            "functional": oracle.get("functional") is True,
            "oracle_secure": oracle.get("secure") is True,
            "oracle_insecure": oracle.get("secure") is False,
            "functional_and_secure": (
                oracle.get("functional") is True and oracle.get("secure") is True
            ),
            "functional_but_insecure": (
                oracle.get("functional") is True and oracle.get("secure") is False
            ),
            "oracle_error": oracle.get("error") or "",
        }
        for tool, runs in tools.items():
            run = runs[sample.id]
            row[f"{tool}_ok"] = run.ok
            row[f"{tool}_findings"] = len(_security_findings(run))
            row[f"{tool}_exact"] = (
                _confirmed_prediction(run, target)
                if tool == "vibeguard_confirmed"
                else _exact_prediction(run, target)
            )
            row[f"{tool}_family"] = (
                _confirmed_family_prediction(run, target)
                if tool == "vibeguard_confirmed"
                else _family_prediction(run, target)
            )
            row[f"{tool}_any"] = bool(_security_findings(run))
            row[f"{tool}_elapsed_ms"] = round(run.elapsed_ms, 3)
            row[f"{tool}_error"] = run.error or ""
        target_statuses = getattr(
            dynamic_runs[sample.id], "dynamic_statuses", {}
        ).get(target, set())
        row["vibeguard_target_probe_status"] = "|".join(sorted(target_statuses))
        row["vibeguard_risk_score"] = round(
            float(getattr(dynamic_runs[sample.id], "risk_score", 0.0)), 4
        )
        sample_rows.append(row)
    _write_csv(out_dir / "cweval_per_sample.csv", sample_rows)

    detection_rows = []
    for tool in tools:
        for endpoint in ("exact", "family"):
            detection_rows.append(_detection_metric_row(
                sample_rows,
                tool=tool,
                endpoint=endpoint,
                prediction_key=f"{tool}_{endpoint}",
                iterations=bootstrap_iterations,
            ))
    _write_csv(out_dir / "cweval_detection_metrics.csv", detection_rows)

    outcome_rows = _model_outcomes(sample_rows, bootstrap_iterations)
    at_k_rows = _at_k_rows(sample_rows, bootstrap_iterations)
    prevalence_rows = _prevalence_rows(oracle_samples, vibeguard_runs)
    _write_csv(out_dir / "cweval_model_outcomes.csv", outcome_rows)
    _write_csv(out_dir / "cweval_secure_at_k.csv", at_k_rows)
    _write_csv(out_dir / "cweval_finding_prevalence.csv", prevalence_rows)

    probe_rows = [
        row for row in sample_rows if row["vibeguard_target_probe_status"]
    ]
    probe_metrics = None
    if probe_rows:
        probe_metrics = _detection_metric_row(
            probe_rows,
            tool="vibeguard_probe",
            endpoint="confirmed_within_target_probe_eligible_static_findings",
            prediction_key="vibeguard_confirmed_exact",
            iterations=bootstrap_iterations,
        )
    _write_csv(out_dir / "cweval_probe_validation.csv", probe_rows)

    labels = [bool(row["oracle_insecure"]) for row in sample_rows]
    task_ids = [row["task_id"] for row in sample_rows]
    comparisons = []
    for baseline in ("bandit", "semgrep", "vibeguard_no_taint"):
        first = [bool(row["vibeguard_exact"]) for row in sample_rows]
        second = [bool(row[f"{baseline}_exact"]) for row in sample_rows]
        first_correct = [label == prediction for label, prediction in zip(labels, first)]
        second_correct = [label == prediction for label, prediction in zip(labels, second)]
        comparisons.append({
            "first": "vibeguard",
            "second": baseline,
            "endpoint": "exact",
            "mcnemar": mcnemar_exact(first_correct, second_correct),
            "f1_difference_cluster_ci95": _round_interval(
                clustered_paired_bootstrap_metric_difference(
                    task_ids,
                    labels,
                    first,
                    second,
                    iterations=bootstrap_iterations,
                )
            ),
        })

    risk_scores = [float(row["vibeguard_risk_score"]) for row in sample_rows]
    risk_auroc = auroc(labels, risk_scores)
    statistics = {
        "comparisons": comparisons,
        "vibeguard_risk_auroc": round(risk_auroc, 4),
        "bootstrap_iterations": bootstrap_iterations,
        "bootstrap_unit": "CWEval task",
        "probe_validation": probe_metrics,
    }
    (out_dir / "statistical_tests.json").write_text(
        json.dumps(statistics, indent=2), encoding="utf-8"
    )

    sallm = load_sallm()
    securityeval = load_securityeval()
    evalplus = load_evalplus(evalplus_path, subsets=("humanevalplus",))
    cross_rows, _ = _cross_dataset_rows(
        {"sallm": sallm, "securityeval": securityeval, "evalplus": evalplus},
        {
            "vibeguard": lambda data: run_vibeguard_batch(data, enable_taint=True),
            "bandit": run_bandit_batch,
            "semgrep": run_semgrep_batch,
        },
    )
    _write_csv(out_dir / "cross_dataset_detection.csv", cross_rows)

    from experiments.rq7_probe_accuracy import run_rq7

    run_rq7(out_dir / "probe_mutation")
    probe_mutation = json.loads(
        (out_dir / "probe_mutation" / "probe_accuracy.json").read_text(
            encoding="utf-8"
        )
    )["overall"]

    manifest = _manifest(corpus_path)
    (out_dir / "environment_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    summary = {
        "cweval_corpus_samples": len(samples),
        "cweval_samples": len(sample_rows),
        "cweval_tasks": len({row["task_id"] for row in sample_rows}),
        "cweval_excluded_samples": len(exclusion_rows),
        "cweval_excluded_tasks": sorted({row["task_id"] for row in exclusion_rows}),
        "sources": sorted({row["source"] for row in sample_rows}),
        "detection_metrics": detection_rows,
        "model_outcomes": outcome_rows,
        "secure_at_k": at_k_rows,
        "cross_dataset": cross_rows,
        "statistics": statistics,
        "probe_mutation": probe_mutation,
        "tool_errors": {
            tool: sum(not runs[sample.id].ok for sample in oracle_samples)
            for tool, runs in tools.items()
        },
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, help="Oracle-annotated CWEval corpus")
    parser.add_argument("--out-dir", default="results/research_v4")
    parser.add_argument(
        "--evalplus-path",
        default="dataset/evalplus",
        help="Official HumanEvalPlus JSONL file or containing directory",
    )
    parser.add_argument("--bootstrap-iterations", type=int, default=5000)
    args = parser.parse_args()
    summary = run_evaluation(
        args.corpus,
        args.out_dir,
        evalplus_path=args.evalplus_path,
        bootstrap_iterations=args.bootstrap_iterations,
    )
    print(json.dumps({
        "cweval_corpus_samples": summary["cweval_corpus_samples"],
        "cweval_samples": summary["cweval_samples"],
        "cweval_excluded_samples": summary["cweval_excluded_samples"],
        "cweval_excluded_tasks": summary["cweval_excluded_tasks"],
        "tool_errors": summary["tool_errors"],
    }, indent=2))


if __name__ == "__main__":
    main()
