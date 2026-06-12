"""Better Evaluation Methodology: Detection Rate + Family-Grouped P/R/F1.

Addresses single-label ground-truth bias in standard CWE-space evaluation:

  Problem: Each sample has one CWE label. VibeGuard detecting additional
  *correct* vulnerabilities in the same code is counted as FP.

Three complementary metrics computed here:

  1. Detection rate   -- % of known-vulnerable samples with ANY security finding.
                        Label-free: rewards catching any real issue.
  2. False alarm rate -- % of benign (EvalPlus) samples with security findings.
                        Measures noise on known-clean code.
  3. Family-grouped P/R/F1 -- Maps CWE labels to canonical family names so that
                        CWE-94 (code injection) detected as CWE-95 (eval injection)
                        is NOT a FP; both belong to the "injection" family.

Datasets:
  - SALLM          dataset/sallm/dataset.jsonl       (100 insecure samples)
  - SecurityEval   HuggingFace s2e-lab/SecurityEval  (121 insecure samples)
  - EvalPlus       evalplus HumanEval+ canonical      (164 benign samples)

Usage:
    python -m experiments.run_detection_study [--out-dir results/detection_study]
    python -m experiments.run_detection_study --no-evalplus   # skip EvalPlus download
    python -m experiments.run_detection_study --no-securityeval --no-evalplus
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from experiments.cwe_families import cwes_to_families
from experiments.baselines import available_tools, run_tool, SECURITY_TOOLS

# Matches both "CWE-94" and "cwe94" formats (SALLM uses the latter)
_CWE_RE = re.compile(r"CWE[-_]?(\d+)", re.IGNORECASE)


# ── Sample model ──────────────────────────────────────────────────────────────

class Sample:
    __slots__ = ("id", "source", "code", "gt_cwes", "is_benign")

    def __init__(self, id: str, source: str, code: str,
                 gt_cwes: Set[str], is_benign: bool) -> None:
        self.id = id
        self.source = source
        self.code = code
        self.gt_cwes = gt_cwes
        self.is_benign = is_benign


def _norm_cwe(text: str) -> Optional[str]:
    m = _CWE_RE.search(text)
    return f"CWE-{int(m.group(1))}" if m else None


# ── Dataset loaders ───────────────────────────────────────────────────────────

def load_sallm(path: Path) -> List[Sample]:
    samples = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        cwe = _norm_cwe(r["id"])
        samples.append(Sample(
            id=r["id"],
            source="sallm",
            code=r["insecure_code"],
            gt_cwes={cwe} if cwe else set(),
            is_benign=False,
        ))
    return samples


def load_securityeval() -> List[Sample]:
    import datasets as hf_datasets
    ds = hf_datasets.load_dataset("s2e-lab/SecurityEval", split="train")
    samples = []
    for r in ds:
        cwe = _norm_cwe(r["ID"])
        samples.append(Sample(
            id=r["ID"],
            source="securityeval",
            code=r["Insecure_code"],
            gt_cwes={cwe} if cwe else set(),
            is_benign=False,
        ))
    return samples


def load_evalplus() -> List[Sample]:
    from evalplus.data import get_human_eval_plus
    problems = get_human_eval_plus()
    return [
        Sample(
            id=task_id,
            source="evalplus",
            code=prob["prompt"] + prob["canonical_solution"],
            gt_cwes=set(),
            is_benign=True,
        )
        for task_id, prob in problems.items()
    ]


# ── Metrics accumulator ───────────────────────────────────────────────────────

class DetectionResult:
    def __init__(self, tool: str, dataset: str) -> None:
        self.tool = tool
        self.dataset = dataset
        # detection rate (vulnerable samples)
        self.n_vulnerable = 0
        self.n_detected_any = 0
        # false alarm rate (benign samples)
        self.n_benign = 0
        self.n_false_alarm = 0
        # standard single-label P/R/F1
        self.tp_single = 0
        self.fp_single = 0
        self.fn_single = 0
        # family-grouped P/R/F1
        self.tp_family = 0
        self.fp_family = 0
        self.fn_family = 0

    @property
    def is_benign_dataset(self) -> bool:
        return self.dataset in ("evalplus", "evalplus_benign")

    @property
    def detection_rate(self) -> float:
        return self.n_detected_any / self.n_vulnerable if self.n_vulnerable else 0.0

    @property
    def false_alarm_rate(self) -> float:
        return self.n_false_alarm / self.n_benign if self.n_benign else 0.0

    @staticmethod
    def _prf(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
        p = tp / (tp + fp) if (tp + fp) else 1.0
        r = tp / (tp + fn) if (tp + fn) else 1.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        return round(p, 4), round(r, 4), round(f1, 4)

    @property
    def single_prf(self) -> Tuple[float, float, float]:
        return self._prf(self.tp_single, self.fp_single, self.fn_single)

    @property
    def family_prf(self) -> Tuple[float, float, float]:
        return self._prf(self.tp_family, self.fp_family, self.fn_family)

    def to_dict(self) -> dict:
        sp, sr, sf1 = self.single_prf
        fgp, fgr, fgf1 = self.family_prf
        return {
            "tool": self.tool,
            "dataset": self.dataset,
            "n_vulnerable": self.n_vulnerable,
            "n_detected_any": self.n_detected_any,
            "detection_rate": round(self.detection_rate, 4),
            "n_benign": self.n_benign,
            "n_false_alarm": self.n_false_alarm,
            "false_alarm_rate": round(self.false_alarm_rate, 4),
            "tp_single": self.tp_single,
            "fp_single": self.fp_single,
            "fn_single": self.fn_single,
            "precision_single": sp,
            "recall_single": sr,
            "f1_single": sf1,
            "tp_family": self.tp_family,
            "fp_family": self.fp_family,
            "fn_family": self.fn_family,
            "precision_family": fgp,
            "recall_family": fgr,
            "f1_family": fgf1,
        }


# ── Evaluation helpers ────────────────────────────────────────────────────────

def _security_cwes(run) -> Set[str]:
    if not (run and run.ok):
        return set()
    return {f.cwe for f in run.findings if f.cwe and f.category == "security"}


def _has_any_security(run) -> bool:
    if not (run and run.ok):
        return False
    return any(f.category == "security" for f in run.findings)


def _family_tpfpfn(detected_cwes: Set[str], gt_cwes: Set[str]) -> Tuple[int, int, int]:
    """TP/FP/FN at CWE-family granularity."""
    det_fam = cwes_to_families(detected_cwes)
    gt_fam = cwes_to_families(gt_cwes)
    tp = len(det_fam & gt_fam)
    fp = len(det_fam - gt_fam)
    fn = len(gt_fam - det_fam)
    return tp, fp, fn


def evaluate_dataset(
    samples: List[Sample],
    tools: List[str],
    sec_tools: Tuple[str, ...],
    dataset_name: str,
    show_progress: bool = True,
) -> Dict[str, DetectionResult]:
    results: Dict[str, DetectionResult] = {
        t: DetectionResult(tool=t, dataset=dataset_name)
        for t in sec_tools
    }
    n = len(samples)
    for i, s in enumerate(samples):
        if show_progress and (i + 1) % 25 == 0:
            print(f"  [{i+1}/{n}] {s.id}")

        runs = {t: run_tool(t, s.code) for t in tools}

        for tool in sec_tools:
            dr = results[tool]
            run = runs.get(tool)
            detected = _security_cwes(run)
            has_sec = _has_any_security(run)

            if s.is_benign:
                dr.n_benign += 1
                if has_sec:
                    dr.n_false_alarm += 1
            else:
                dr.n_vulnerable += 1
                if has_sec:
                    dr.n_detected_any += 1

                gt = s.gt_cwes
                # single-label
                dr.tp_single += len(detected & gt)
                dr.fp_single += len(detected - gt)
                dr.fn_single += len(gt - detected)
                # family-grouped (only when gt is non-empty)
                if gt:
                    tp, fp, fn = _family_tpfpfn(detected, gt)
                    dr.tp_family += tp
                    dr.fp_family += fp
                    dr.fn_family += fn
                else:
                    # no label — any detection is a potential FP
                    dr.fp_family += len(detected)

    return results


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="results/detection_study")
    parser.add_argument("--sallm-path", default="dataset/sallm/dataset.jsonl")
    parser.add_argument("--no-securityeval", action="store_true")
    parser.add_argument("--no-evalplus", action="store_true")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tools = available_tools()
    sec_tools = tuple(t for t in SECURITY_TOOLS if t in tools)
    print(f"Tools: {tools}")
    print(f"Security tools: {sec_tools}")

    all_results: List[DetectionResult] = []

    # ── SALLM ─────────────────────────────────────────────────────────────────
    sallm_path = Path(args.sallm_path)
    if sallm_path.exists():
        sallm = load_sallm(sallm_path)
        print(f"\nSALLM: {len(sallm)} samples")
        dr = evaluate_dataset(sallm, tools, sec_tools, "sallm")
        all_results.extend(dr.values())
    else:
        print(f"WARNING: SALLM not found at {sallm_path} — skipping", file=sys.stderr)

    # ── SecurityEval ──────────────────────────────────────────────────────────
    if not args.no_securityeval:
        try:
            seceval = load_securityeval()
            print(f"\nSecurityEval: {len(seceval)} samples")
            dr = evaluate_dataset(seceval, tools, sec_tools, "securityeval")
            all_results.extend(dr.values())
        except Exception as e:
            print(f"WARNING: SecurityEval failed ({e}) — skipping", file=sys.stderr)

    # ── EvalPlus (benign false-alarm baseline) ────────────────────────────────
    if not args.no_evalplus:
        try:
            evalplus = load_evalplus()
            print(f"\nEvalPlus: {len(evalplus)} benign samples")
            dr = evaluate_dataset(evalplus, tools, sec_tools, "evalplus")
            all_results.extend(dr.values())
        except Exception as e:
            print(f"WARNING: EvalPlus failed ({e}) — skipping", file=sys.stderr)

    if not all_results:
        print("ERROR: No datasets produced results.", file=sys.stderr)
        sys.exit(1)

    # ── Write artifacts ────────────────────────────────────────────────────────
    rows = [r.to_dict() for r in all_results]
    csv_path = out_dir / "detection_study.csv"
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "description": (
            "Better evaluation: detection rate + family-grouped P/R/F1 + false alarm rate. "
            "Addresses single-label ground-truth bias where correct detections "
            "of unlabeled vulnerabilities are counted as FPs."
        ),
        "tools": list(sec_tools),
        "results": rows,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    # ── Print results ──────────────────────────────────────────────────────────
    vuln_results = [r for r in all_results if not r.is_benign_dataset]
    benign_results = [r for r in all_results if r.is_benign_dataset]

    if vuln_results:
        print(f"\n{'='*72}")
        print("1. DETECTION RATE  (% vulnerable samples with any security finding)")
        print(f"{'='*72}")
        print(f"  {'Dataset':<18} {'Tool':<12} {'Detected/Total':>16} {'Rate':>7}")
        print("  " + "-" * 60)
        for r in vuln_results:
            frac = f"{r.n_detected_any}/{r.n_vulnerable}"
            print(f"  {r.dataset:<18} {r.tool:<12} {frac:>16} {r.detection_rate:>7.1%}")

    if benign_results:
        print(f"\n{'='*72}")
        print("2. FALSE ALARM RATE  (% benign EvalPlus samples with spurious findings)")
        print(f"{'='*72}")
        print(f"  {'Dataset':<18} {'Tool':<12} {'Alarms/Total':>16} {'FAR':>7}")
        print("  " + "-" * 60)
        for r in benign_results:
            frac = f"{r.n_false_alarm}/{r.n_benign}"
            print(f"  {r.dataset:<18} {r.tool:<12} {frac:>16} {r.false_alarm_rate:>7.1%}")

    if vuln_results:
        print(f"\n{'='*72}")
        print("3. P/R/F1: Single-Label  vs  Family-Grouped")
        print(f"{'='*72}")
        print(f"  {'Dataset':<18} {'Tool':<12} {'Method':<16} "
              f"{'TP':>4} {'FP':>4} {'FN':>4} {'P':>6} {'R':>6} {'F1':>6}")
        print("  " + "-" * 72)
        for r in vuln_results:
            sp, sr, sf1 = r.single_prf
            fgp, fgr, fgf1 = r.family_prf
            delta = fgf1 - sf1
            sign = "+" if delta >= 0 else ""
            print(f"  {r.dataset:<18} {r.tool:<12} {'single-label':<16} "
                  f"{r.tp_single:>4} {r.fp_single:>4} {r.fn_single:>4} "
                  f"{sp:>6.3f} {sr:>6.3f} {sf1:>6.3f}")
            print(f"  {'':<18} {'':<12} {'family-grouped':<16} "
                  f"{r.tp_family:>4} {r.fp_family:>4} {r.fn_family:>4} "
                  f"{fgp:>6.3f} {fgr:>6.3f} {fgf1:>6.3f}  ({sign}{delta:.3f})")
            print()

    print(f"\nArtifacts written to {out_dir}/")
    print(f"  detection_study.csv")
    print(f"  summary.json")


if __name__ == "__main__":
    main()
