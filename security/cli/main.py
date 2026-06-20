import sys
import argparse
import json
from pathlib import Path
from typing import Optional

from security.core.scanner import Scanner
from fixers.engine import fix_source
from security.models.finding import Severity
from security.reporters.json_reporter import JsonReporter
from security.reporters.text import TextReporter
from security.utils.file_utils import collect_python_files


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vibeguard",
        description="VibeGuard — Static security analyzer for Python code.",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    scan = sub.add_parser("scan", help="Scan a Python file or directory for security issues.")
    scan.add_argument("path", help="Path to a Python file or directory.")
    scan.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text).",
    )
    scan.add_argument(
        "--output", metavar="FILE",
        help="Write output to FILE instead of stdout.",
    )
    scan.add_argument(
        "--severity", choices=["low", "medium", "high"],
        help="Minimum severity level to report.",
    )
    scan.add_argument("--quiet", action="store_true", help="Suppress non-finding output.")
    scan.add_argument(
        "--no-snippet", dest="include_snippet", action="store_false",
        help="Exclude code snippets from output.",
    )
    scan.add_argument(
        "--dynamic-verify", action="store_true",
        help="Run dynamic sandbox probes to confirm/dismiss findings (slower).",
    )
    scan.add_argument(
        "--fix", action="store_true",
        help="Apply safe automatic fixes to detected issues.",
    )
    scan.add_argument(
        "--dry-run", action="store_true",
        help="With --fix, show a unified diff instead of writing changes.",
    )
    scan.add_argument(
        "--profile", action="store_true",
        help="Run the sandbox profiler to report CPU, memory, wall time, and energy estimates.",
    )
    scan.set_defaults(include_snippet=True)

    return parser


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 ** 2:.2f} MB"


def _print_profile(totals: dict, label: str = "Runtime Profile") -> None:
    print(f"\n{label}")
    print(f"  CPU time    : {totals.get('cpu_time_seconds', 0):.4f}s")
    print(f"  Wall time   : {totals.get('wall_time_seconds', 0):.4f}s")
    mem = totals.get("memory_peak_bytes", 0)
    print(f"  Memory peak : {_format_bytes(mem)}")
    energy = totals.get("energy_joules_estimate")
    if energy is not None:
        model = totals.get("energy_model", "")
        print(f"  Energy est. : {energy:.6f} J  [{model}]")


def _print_perf_delta(delta: dict) -> None:
    print("\n  Performance delta (before → after fix):")

    def _row(label: str, before, after, delta_val, pct=None, unit: str = "") -> None:
        if before is None or after is None:
            return
        sign = "+" if (delta_val or 0) > 0 else ""
        pct_str = f"  ({sign}{pct}%)" if pct is not None else ""
        print(f"    {label:<18}: {before}{unit} → {after}{unit}  Δ {sign}{delta_val}{unit}{pct_str}")

    _row("CPU time (s)", delta.get("cpu_time_before"), delta.get("cpu_time_after"),
         delta.get("cpu_time_delta"), delta.get("cpu_time_pct"), "s")
    _row("Wall time (s)", delta.get("wall_time_before"), delta.get("wall_time_after"),
         delta.get("wall_time_delta"), delta.get("wall_time_pct"), "s")

    mb = delta.get("memory_peak_before")
    ma = delta.get("memory_peak_after")
    md = delta.get("memory_peak_delta")
    if mb is not None and ma is not None and md is not None:
        print(f"    {'Memory peak':<18}: {_format_bytes(mb)} → {_format_bytes(ma)}  "
              f"Δ {'+' if md > 0 else ''}{_format_bytes(abs(md))}")

    eb = delta.get("energy_before")
    ea = delta.get("energy_after")
    ed = delta.get("energy_delta")
    if eb is not None and ea is not None and ed is not None:
        sign = "+" if ed > 0 else ""
        model = delta.get("energy_model", "")
        print(f"    {'Energy est. (J)':<18}: {eb:.6f} → {ea:.6f}  Δ {sign}{ed:.6f}  [{model}]")


def _run_profile_on_files(target: str, quiet: bool = False) -> None:
    try:
        from sandbox.profiler import measure_code  # noqa: PLC0415
    except ImportError:
        print("vibeguard: sandbox profiler not available.", file=sys.stderr)
        return

    files = collect_python_files(target)
    for fp in files:
        try:
            source = Path(fp).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        result = measure_code(source)
        if result.get("ok") and result.get("totals"):
            _print_profile(result["totals"], label=f"Runtime Profile: {fp}")
        elif not quiet:
            err = result.get("error_message", "unknown error")
            print(f"\nRuntime Profile: {fp} — skipped ({result.get('error_type', 'error')}: "
                  f"{err[:80].strip()})")


def _run_fix(target: str, args: argparse.Namespace) -> int:
    files = collect_python_files(target)
    results = []
    total_applied = 0
    any_unsafe = False

    for file_path in files:
        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"vibeguard: error reading {file_path}: {exc}", file=sys.stderr)
            continue

        with_profile = getattr(args, "profile", False)
        result = fix_source(source, filename=file_path, with_profile=with_profile)
        if not result.safe and result.note:
            any_unsafe = True
        if not result.changed:
            continue

        total_applied += len(result.applied)
        results.append((file_path, result))

        if not args.dry_run:
            Path(file_path).write_text(result.fixed_code, encoding="utf-8")

    if args.format == "json":
        payload = {
            "fixed_files": [
                {
                    "file": fp,
                    "applied": [a.to_dict() for a in r.applied],
                    "findings_before": r.findings_before,
                    "findings_after": r.findings_after,
                    "diff": r.unified_diff(fp),
                    **({"perf_delta": r.perf_delta()} if r.perf_delta() is not None else {}),
                }
                for fp, r in results
            ],
            "total_applied": total_applied,
            "dry_run": args.dry_run,
        }
        print(json.dumps(payload, indent=2))
        return 0

    if not results:
        print("No auto-fixable issues found.")
        return 0

    for file_path, result in results:
        verb = "Would fix" if args.dry_run else "Fixed"
        print(f"{verb} {file_path} ({len(result.applied)} change(s), "
              f"{result.findings_before} -> {result.findings_after} findings):")
        for applied in result.applied:
            print(f"  line {applied.line}: {applied.description}")
        delta = result.perf_delta()
        if delta is not None:
            _print_perf_delta(delta)
        if args.dry_run:
            print(result.unified_diff(file_path))
        print()

    action = "Proposed" if args.dry_run else "Applied"
    print(f"{action} {total_applied} fix(es) across {len(results)} file(s).")
    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(2)

    target = args.path
    if not Path(target).exists():
        print(f"vibeguard: error: path does not exist: {target}", file=sys.stderr)
        sys.exit(2)

    if getattr(args, "fix", False):
        sys.exit(_run_fix(target, args))

    min_severity = Severity[args.severity.upper()] if args.severity else None
    dynamic_verify = getattr(args, "dynamic_verify", False)
    scanner = Scanner(min_severity=min_severity, include_snippet=args.include_snippet, dynamic_verify=dynamic_verify)
    result = scanner.scan(target)

    writing_to_file = bool(args.output)
    if args.format == "json":
        reporter: JsonReporter | TextReporter = JsonReporter()
    else:
        reporter = TextReporter(use_color=not writing_to_file)

    output = reporter.report(result)

    if writing_to_file:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        if not args.quiet:
            print(f"Report written to {args.output}")
    else:
        print(output)

    if not args.quiet and args.format != "json":
        score = result.exploitability_score
        label = "LOW" if score < 0.2 else "MEDIUM" if score < 0.5 else "HIGH"
        print(f"Exploitability score: {score:.4f} ({label})")

    if getattr(args, "profile", False):
        _run_profile_on_files(target, quiet=getattr(args, "quiet", False))

    sys.exit(1 if result.findings else 0)


if __name__ == "__main__":
    main()
