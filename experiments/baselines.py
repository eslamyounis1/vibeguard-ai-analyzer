"""Baseline-tool adapters and security precision/recall in CWE space.

Each adapter runs an external analyzer over a code sample and normalizes the
output to :class:`ToolFinding`. For security comparison we project every tool's
findings into CWE space (VibeGuard via its rule->CWE metadata, Bandit/Semgrep
via their reported CWEs) so precision/recall can be computed uniformly against
ground-truth CWE labels.

External tools are optional; ``available()`` is checked before running so the
module degrades gracefully when a tool is not installed.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from security.core.scanner import Scanner
from security.rules.security.metadata import _METADATA_BY_RULE

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def _norm_cwe(text: str) -> Optional[str]:
    match = _CWE_RE.search(str(text))
    return f"CWE-{match.group(1)}" if match else None


def rule_to_cwe(rule_id: str) -> Optional[str]:
    meta = _METADATA_BY_RULE.get(rule_id)
    return _norm_cwe(meta.cwe) if meta else None


def labels_to_cwes(labels: List[str]) -> Set[str]:
    cwes: Set[str] = set()
    for label in labels:
        direct = _norm_cwe(label)
        cwe = direct or rule_to_cwe(label)
        if cwe:
            cwes.add(cwe)
    return cwes


@dataclass
class ToolFinding:
    tool: str
    rule: str
    cwe: Optional[str] = None
    line: Optional[int] = None
    severity: Optional[str] = None
    category: str = "security"


@dataclass
class ToolRun:
    tool: str
    ok: bool
    findings: List[ToolFinding] = field(default_factory=list)
    elapsed_ms: float = 0.0
    error: Optional[str] = None

    @property
    def cwes(self) -> Set[str]:
        return {f.cwe for f in self.findings if f.cwe}


def _write_temp(code: str) -> Path:
    tmp = tempfile.NamedTemporaryFile(prefix="vg_bl_", suffix=".py", delete=False, mode="w", encoding="utf-8")
    tmp.write(code)
    tmp.close()
    return Path(tmp.name)


def _run(cmd: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


# ── Adapters ──────────────────────────────────────────────────────────────────

def run_vibeguard(code: str) -> ToolRun:
    start = time.perf_counter()
    result = Scanner().scan_source(code)
    findings = [
        ToolFinding(
            tool="vibeguard",
            rule=f.rule_id,
            cwe=_norm_cwe(f.cwe) if f.cwe else None,
            line=f.line,
            severity=f.severity.value,
            category=f.category.value.lower(),
        )
        for f in result.findings
    ]
    return ToolRun("vibeguard", ok=True, findings=findings, elapsed_ms=(time.perf_counter() - start) * 1000)


def run_bandit(code: str) -> ToolRun:
    if shutil.which("bandit") is None:
        return ToolRun("bandit", ok=False, error="bandit not installed")
    path = _write_temp(code)
    start = time.perf_counter()
    try:
        proc = _run(["bandit", "-f", "json", "-q", str(path)])
        data = json.loads(proc.stdout or "{}")
        findings = []
        for r in data.get("results", []):
            cwe_id = (r.get("issue_cwe") or {}).get("id")
            findings.append(
                ToolFinding(
                    tool="bandit",
                    rule=r.get("test_id", "?"),
                    cwe=f"CWE-{cwe_id}" if cwe_id else None,
                    line=r.get("line_number"),
                    severity=r.get("issue_severity"),
                )
            )
        return ToolRun("bandit", ok=True, findings=findings, elapsed_ms=(time.perf_counter() - start) * 1000)
    except Exception as exc:
        return ToolRun("bandit", ok=False, error=str(exc))
    finally:
        path.unlink(missing_ok=True)


def run_semgrep(code: str) -> ToolRun:
    if shutil.which("semgrep") is None:
        return ToolRun("semgrep", ok=False, error="semgrep not installed")
    path = _write_temp(code)
    start = time.perf_counter()
    try:
        proc = _run(["semgrep", "--json", "--quiet", "--config", "p/python", str(path)], timeout=120)
        data = json.loads(proc.stdout or "{}")
        findings = []
        for r in data.get("results", []):
            meta = (r.get("extra") or {}).get("metadata") or {}
            cwe_field = meta.get("cwe")
            cwe = None
            if isinstance(cwe_field, list) and cwe_field:
                cwe = _norm_cwe(cwe_field[0])
            elif isinstance(cwe_field, str):
                cwe = _norm_cwe(cwe_field)
            findings.append(
                ToolFinding(
                    tool="semgrep",
                    rule=r.get("check_id", "?"),
                    cwe=cwe,
                    line=(r.get("start") or {}).get("line"),
                    severity=(r.get("extra") or {}).get("severity"),
                )
            )
        return ToolRun("semgrep", ok=True, findings=findings, elapsed_ms=(time.perf_counter() - start) * 1000)
    except Exception as exc:
        return ToolRun("semgrep", ok=False, error=str(exc))
    finally:
        path.unlink(missing_ok=True)


def run_ruff(code: str) -> ToolRun:
    if shutil.which("ruff") is None:
        return ToolRun("ruff", ok=False, error="ruff not installed")
    path = _write_temp(code)
    start = time.perf_counter()
    try:
        proc = _run(["ruff", "check", "--output-format", "json", str(path)])
        data = json.loads(proc.stdout or "[]")
        findings = [
            ToolFinding(tool="ruff", rule=item.get("code") or "?", line=(item.get("location") or {}).get("row"), category="quality")
            for item in data
        ]
        return ToolRun("ruff", ok=True, findings=findings, elapsed_ms=(time.perf_counter() - start) * 1000)
    except Exception as exc:
        return ToolRun("ruff", ok=False, error=str(exc))
    finally:
        path.unlink(missing_ok=True)


def run_pylint(code: str) -> ToolRun:
    if shutil.which("pylint") is None:
        return ToolRun("pylint", ok=False, error="pylint not installed")
    path = _write_temp(code)
    start = time.perf_counter()
    try:
        proc = _run(["pylint", "--output-format=json", str(path)])
        data = json.loads(proc.stdout or "[]")
        findings = [
            ToolFinding(tool="pylint", rule=item.get("symbol") or item.get("message-id") or "?", line=item.get("line"), category="quality")
            for item in data
        ]
        return ToolRun("pylint", ok=True, findings=findings, elapsed_ms=(time.perf_counter() - start) * 1000)
    except Exception as exc:
        return ToolRun("pylint", ok=False, error=str(exc))
    finally:
        path.unlink(missing_ok=True)


def run_radon(code: str) -> ToolRun:
    if shutil.which("radon") is None:
        return ToolRun("radon", ok=False, error="radon not installed")
    path = _write_temp(code)
    start = time.perf_counter()
    try:
        proc = _run(["radon", "cc", "-j", str(path)])
        data = json.loads(proc.stdout or "{}")
        findings = []
        for blocks in data.values():
            for block in blocks:
                findings.append(
                    ToolFinding(
                        tool="radon",
                        rule=f"complexity:{block.get('rank')}",
                        line=block.get("lineno"),
                        category="complexity",
                    )
                )
        return ToolRun("radon", ok=True, findings=findings, elapsed_ms=(time.perf_counter() - start) * 1000)
    except Exception as exc:
        return ToolRun("radon", ok=False, error=str(exc))
    finally:
        path.unlink(missing_ok=True)


_ADAPTERS = {
    "vibeguard": run_vibeguard,
    "bandit": run_bandit,
    "semgrep": run_semgrep,
    "ruff": run_ruff,
    "pylint": run_pylint,
    "radon": run_radon,
}

# Tools whose findings are projected into CWE space for precision/recall.
SECURITY_TOOLS = ("vibeguard", "bandit", "semgrep")


def available_tools() -> List[str]:
    out = ["vibeguard"]
    for tool in _ADAPTERS:
        if tool != "vibeguard" and shutil.which(tool) is not None:
            out.append(tool)
    return out


def run_tool(tool: str, code: str) -> ToolRun:
    adapter = _ADAPTERS.get(tool)
    if adapter is None:
        raise ValueError(f"Unknown tool: {tool!r}. Known: {sorted(_ADAPTERS)}")
    return adapter(code)


@dataclass
class PrecisionRecall:
    tool: str
    tp: int
    fp: int
    fn: int

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


def security_precision_recall(
    samples_cwes: List[Set[str]],
    tool_runs_per_sample: List[Dict[str, ToolRun]],
    tools: tuple = SECURITY_TOOLS,
    scope_to: Optional[Set[str]] = None,
) -> Dict[str, PrecisionRecall]:
    """Compute CWE-space precision/recall per security tool over a corpus.

    ``samples_cwes[i]`` is the ground-truth CWE set for sample i;
    ``tool_runs_per_sample[i][tool]`` is that tool's run on sample i.

    When ``scope_to`` is set (e.g. VibeGuard-supported CWEs), both ground truth
    and detections are intersected with that set before counting tp/fp/fn.
    """
    results: Dict[str, PrecisionRecall] = {}
    for tool in tools:
        tp = fp = fn = 0
        for gt, runs in zip(samples_cwes, tool_runs_per_sample):
            if scope_to is not None:
                gt = gt & scope_to
            run = runs.get(tool)
            detected = run.cwes if (run and run.ok) else set()
            if scope_to is not None:
                detected = detected & scope_to
            tp += len(detected & gt)
            fp += len(detected - gt)
            fn += len(gt - detected)
        results[tool] = PrecisionRecall(tool=tool, tp=tp, fp=fp, fn=fn)
    return results


def evaluate_sample(
    sample_id: str,
    task_id: str,
    source: str,
    code: str,
    expected_labels: List[str],
    tools: Optional[List[str]] = None,
    scope_to: Optional[Set[str]] = None,
) -> tuple[List[dict], Dict[str, ToolRun]]:
    """Run all tools on one sample; return per-tool row dicts and raw runs."""
    tools = tools or available_tools()
    gt = labels_to_cwes(expected_labels)
    if scope_to is not None:
        gt = gt & scope_to
    runs = {t: run_tool(t, code) for t in tools}
    rows = []
    for tool in tools:
        run = runs[tool]
        detected = run.cwes if run.ok else set()
        if scope_to is not None:
            detected = detected & scope_to
        rows.append({
            "sample_id": sample_id,
            "task_id": task_id,
            "source": source,
            "tool": tool,
            "ok": run.ok,
            "error": run.error,
            "elapsed_ms": round(run.elapsed_ms, 2),
            "n_findings": len(run.findings),
            "detected_cwes": ";".join(sorted(detected)),
            "expected_cwes": ";".join(sorted(gt)),
            "tp": len(detected & gt),
            "fp": len(detected - gt),
            "fn": len(gt - detected),
        })
    return rows, runs


def evaluate_corpus(
    samples: List,
    tools: Optional[List[str]] = None,
    ai_only: bool = False,
    scope_cwes: bool = True,
) -> tuple[List[dict], List[dict], Dict[str, PrecisionRecall]]:
    """Evaluate baseline tools over a corpus.

    Returns (per_sample_rows, aggregate_rows, precision_recall_by_tool).
    """
    from experiments.cwe_scoping import supported_cwes

    tools = tools or available_tools()
    sec_tools = tuple(t for t in SECURITY_TOOLS if t in tools)
    scope = supported_cwes() if scope_cwes else None

    per_sample: List[dict] = []
    all_gts: List[Set[str]] = []
    all_runs: List[Dict[str, ToolRun]] = []

    for s in samples:
        if ai_only and s.source == "human":
            continue
        rows, runs = evaluate_sample(
            s.id, s.task_id, s.source, s.code, s.expected_security_labels, tools, scope
        )
        per_sample.extend(rows)
        all_gts.append(labels_to_cwes(s.expected_security_labels) & scope if scope else labels_to_cwes(s.expected_security_labels))
        all_runs.append({t: runs[t] for t in sec_tools if t in runs})

    pr = security_precision_recall(all_gts, all_runs, tools=sec_tools, scope_to=scope)
    aggregate = [m.to_dict() for m in pr.values()]
    if scope_cwes and scope:
        for row in aggregate:
            row["scoped_to_vibeguard_cwes"] = True
            row["n_scoped_cwes"] = len(scope)
    return per_sample, aggregate, pr
