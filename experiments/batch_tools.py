"""Batch adapters for reproducible static-analysis experiments."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterable

from corpus.schema import CorpusSample
from experiments.baselines import ToolFinding, ToolRun, tool_executable
from security.core.scanner import Scanner

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def _normalise_cwe(value: object) -> str | None:
    match = _CWE_RE.search(str(value))
    return f"CWE-{int(match.group(1))}" if match else None


def _materialise(samples: list[CorpusSample], root: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for index, sample in enumerate(samples):
        name = f"sample_{index:05d}.py"
        (root / name).write_text(sample.code, encoding="utf-8")
        mapping[name] = sample.id
    return mapping


def run_vibeguard_batch(
    samples: Iterable[CorpusSample],
    *,
    enable_taint: bool = True,
    dynamic_verify: bool = False,
) -> dict[str, ToolRun]:
    scanner = Scanner(enable_taint=enable_taint, dynamic_verify=dynamic_verify)
    runs: dict[str, ToolRun] = {}
    for sample in samples:
        start = time.perf_counter()
        result = scanner.scan_source(sample.code, sample.id)
        findings = [
            ToolFinding(
                tool="vibeguard",
                rule=f.rule_id,
                cwe=_normalise_cwe(f.cwe) if f.cwe else None,
                line=f.line,
                severity=f.severity.value,
                category=f.category.value.lower(),
            )
            for f in result.findings
        ]
        run = ToolRun(
            tool="vibeguard",
            ok=result.ok,
            findings=findings,
            elapsed_ms=(time.perf_counter() - start) * 1000,
            error="; ".join(error.message for error in result.parse_errors) or None,
        )
        run.risk_score = result.exploitability_score  # type: ignore[attr-defined]
        dynamic_statuses: dict[str, set[str]] = {}
        for finding in result.findings:
            cwe = _normalise_cwe(finding.cwe) if finding.cwe else None
            if cwe and finding.dynamic_status:
                dynamic_statuses.setdefault(cwe, set()).add(finding.dynamic_status)
        run.dynamic_statuses = dynamic_statuses  # type: ignore[attr-defined]
        runs[sample.id] = run
    return runs


def run_bandit_batch(samples: Iterable[CorpusSample], timeout: int = 300) -> dict[str, ToolRun]:
    sample_list = list(samples)
    runs = {sample.id: ToolRun("bandit", ok=True) for sample in sample_list}
    executable = tool_executable("bandit")
    if executable is None:
        return {sample.id: ToolRun("bandit", ok=False, error="bandit not installed") for sample in sample_list}

    with tempfile.TemporaryDirectory(prefix="vg_bandit_batch_") as tmp:
        root = Path(tmp)
        mapping = _materialise(sample_list, root)
        start = time.perf_counter()
        proc = subprocess.run(
            [executable, "-r", "-f", "json", "-q", str(root)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        elapsed = (time.perf_counter() - start) * 1000
        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            return {
                sample.id: ToolRun("bandit", ok=False, error=f"invalid Bandit JSON: {exc}")
                for sample in sample_list
            }
        for result in payload.get("results", []):
            sample_id = mapping.get(Path(result.get("filename", "")).name)
            if not sample_id:
                continue
            cwe_id = (result.get("issue_cwe") or {}).get("id")
            runs[sample_id].findings.append(ToolFinding(
                tool="bandit",
                rule=result.get("test_id", "?"),
                cwe=f"CWE-{int(cwe_id)}" if cwe_id else None,
                line=result.get("line_number"),
                severity=result.get("issue_severity"),
            ))
        error = None if proc.returncode in (0, 1) else (proc.stderr or "Bandit failed")[:1000]
        for run in runs.values():
            run.ok = error is None
            run.error = error
            run.elapsed_ms = elapsed / max(1, len(sample_list))
    return runs


def _semgrep_security_configs(root: Path) -> list[str]:
    security_dirs = sorted({path for path in root.rglob("security") if path.is_dir()})
    standalone_audit_dirs = [
        path for path in root.rglob("audit") if path.is_dir()
        and not any(parent in security_dirs for parent in path.parents)
    ]
    return [str(path) for path in [*security_dirs, *standalone_audit_dirs]]


def run_semgrep_batch(
    samples: Iterable[CorpusSample],
    *,
    rules_root: str | Path = "dataset/semgrep-rules/python",
    timeout: int = 900,
) -> dict[str, ToolRun]:
    sample_list = list(samples)
    runs = {sample.id: ToolRun("semgrep", ok=True) for sample in sample_list}
    executable = tool_executable("semgrep")
    if executable is None:
        return {sample.id: ToolRun("semgrep", ok=False, error="semgrep not installed") for sample in sample_list}

    configs = _semgrep_security_configs(Path(rules_root))
    if not configs:
        return {
            sample.id: ToolRun("semgrep", ok=False, error=f"no local rules under {rules_root}")
            for sample in sample_list
        }

    with tempfile.TemporaryDirectory(prefix="vg_semgrep_batch_") as tmp:
        root = Path(tmp)
        mapping = _materialise(sample_list, root)
        command = [
            executable,
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
        ]
        for config in configs:
            command.extend(["--config", config])
        command.append(str(root))

        env = os.environ.copy()
        env["HOME"] = str(Path(tempfile.gettempdir()) / "vibeguard-semgrep-home")
        env["SEMGREP_SEND_METRICS"] = "off"
        env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        try:
            import certifi

            env["SSL_CERT_FILE"] = certifi.where()
        except ImportError:
            pass

        start = time.perf_counter()
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        elapsed = (time.perf_counter() - start) * 1000
        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            return {
                sample.id: ToolRun("semgrep", ok=False, error=f"invalid Semgrep JSON: {exc}")
                for sample in sample_list
            }

        for result in payload.get("results", []):
            sample_id = mapping.get(Path(result.get("path", "")).name)
            if not sample_id:
                continue
            extra = result.get("extra") or {}
            metadata = extra.get("metadata") or {}
            cwe_field = metadata.get("cwe")
            values = cwe_field if isinstance(cwe_field, list) else [cwe_field]
            cwes = {
                cwe for value in values if value
                for cwe in [_normalise_cwe(value)] if cwe
            }
            for cwe in cwes or {None}:
                runs[sample_id].findings.append(ToolFinding(
                    tool="semgrep",
                    rule=result.get("check_id", "?"),
                    cwe=cwe,
                    line=(result.get("start") or {}).get("line"),
                    severity=extra.get("severity"),
                ))
        error = None if proc.returncode in (0, 1) else (proc.stderr or "Semgrep failed")[:1000]
        for run in runs.values():
            run.ok = error is None
            run.error = error
            run.elapsed_ms = elapsed / max(1, len(sample_list))
    return runs
