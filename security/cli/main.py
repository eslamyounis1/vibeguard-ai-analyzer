import sys
import argparse
from pathlib import Path

from security.core.scanner import Scanner
from security.models.finding import Severity
from security.reporters.json_reporter import JsonReporter
from security.reporters.text import TextReporter


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
    scan.set_defaults(include_snippet=True)

    return parser


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

    min_severity = Severity[args.severity.upper()] if args.severity else None
    scanner = Scanner(min_severity=min_severity, include_snippet=args.include_snippet)
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

    sys.exit(1 if result.findings else 0)


if __name__ == "__main__":
    main()
