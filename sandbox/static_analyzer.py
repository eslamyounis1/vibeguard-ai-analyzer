"""
Static analysis engine for VibeGuard.

Parses Python source code into an AST and emits structured findings
across three dimensions:
  - CODE_SMELL  : structural / maintainability issues
  - SECURITY    : OWASP-aligned vulnerability patterns
  - PERFORMANCE : algorithmic inefficiency patterns

Each finding is a dict with:
  category   : "CODE_SMELL" | "SECURITY" | "PERFORMANCE"
  rule_id    : short snake_case identifier
  severity   : "critical" | "high" | "medium" | "low" | "info"
  line       : 1-based source line (None if not applicable)
  col        : 0-based column (None if not applicable)
  message    : human-readable description
  suggestion : concrete fix guidance
"""

from __future__ import annotations

import ast
import re
import tokenize
import io
from dataclasses import dataclass, field, asdict
from typing import Optional

# ─── Data model ──────────────────────────────────────────────────────────────

CATEGORIES = ("CODE_SMELL", "SECURITY", "PERFORMANCE")
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    category: str
    rule_id: str
    severity: str
    line: Optional[int]
    col: Optional[int]
    message: str
    suggestion: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalysisResult:
    ok: bool
    error: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        counts = {sev: 0 for sev in SEVERITIES}
        by_category: dict[str, int] = {cat: 0 for cat in CATEGORIES}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            by_category[f.category] = by_category.get(f.category, 0) + 1
        return {
            "ok": self.ok,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total": len(self.findings),
                "by_severity": counts,
                "by_category": by_category,
            },
        }


# ─── Thresholds ───────────────────────────────────────────────────────────────

MAX_FUNCTION_LINES = 50
MAX_FUNCTION_PARAMS = 5
MAX_NESTING_DEPTH = 4
MAX_COGNITIVE_COMPLEXITY = 15  # rough McCabe proxy

# Patterns that suggest hardcoded secrets (value side of assignments).
_SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token"
    r"|private[_-]?key|client[_-]?secret|credentials|db[_-]?pass)",
    re.IGNORECASE,
)
_TRIVIAL_SECRET_VALUE = re.compile(
    r'^["\'][\w@#$%^&*!+=\-./]{4,}["\']$'
)

# Weak hash / crypto algorithms.
_WEAK_HASH_NAMES = {"md5", "sha1", "sha"}
# Insecure random modules for security-sensitive contexts.
_INSECURE_RANDOM_NAMES = {"random", "randint", "randrange", "choice", "shuffle", "sample"}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _node_line(node: ast.AST) -> Optional[int]:
    return getattr(node, "lineno", None)


def _node_col(node: ast.AST) -> Optional[int]:
    return getattr(node, "col_offset", None)


def _func_source_lines(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    try:
        return (node.end_lineno or node.lineno) - node.lineno + 1
    except AttributeError:
        return 0


def _nesting_depth(node: ast.AST) -> int:
    """Return the maximum nesting depth of control-flow inside node."""
    NESTING_NODES = (ast.For, ast.AsyncFor, ast.While, ast.If, ast.With,
                     ast.AsyncWith, ast.Try, ast.ExceptHandler)
    max_depth = [0]

    def walk(n: ast.AST, depth: int) -> None:
        if isinstance(n, NESTING_NODES):
            depth += 1
            max_depth[0] = max(max_depth[0], depth)
        for child in ast.iter_child_nodes(n):
            walk(child, depth)

    walk(node, 0)
    return max_depth[0]


def _cognitive_complexity(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Rough cognitive complexity: +1 per branching node, +1 per nesting level."""
    BRANCH_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While,
                    ast.Try, ast.ExceptHandler, ast.With, ast.AsyncWith,
                    ast.comprehension)
    total = [0]

    def walk(n: ast.AST, depth: int) -> None:
        if isinstance(n, BRANCH_NODES):
            total[0] += 1 + depth
            depth += 1
        elif isinstance(n, ast.BoolOp):
            total[0] += len(n.values) - 1
        for child in ast.iter_child_nodes(n):
            walk(child, depth)

    walk(node, 0)
    return total[0]


def _is_string_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _get_full_attr(node: ast.Attribute) -> str:
    """Reconstruct dotted name like 'hashlib.md5' from an Attribute node."""
    parts = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


# ─── Visitor ─────────────────────────────────────────────────────────────────

class _VibeGuardVisitor(ast.NodeVisitor):
    """Single-pass AST visitor that accumulates findings."""

    def __init__(self, source_lines: list[str]) -> None:
        self.source_lines = source_lines
        self.findings: list[Finding] = []
        self._imports: dict[str, str] = {}   # local_name -> module
        self._import_froms: dict[str, str] = {}  # local_name -> "module.name"
        self._assigned_names: set[str] = set()
        self._used_names: set[str] = set()

    def _add(
        self,
        category: str,
        rule_id: str,
        severity: str,
        node: ast.AST,
        message: str,
        suggestion: str,
    ) -> None:
        self.findings.append(
            Finding(
                category=category,
                rule_id=rule_id,
                severity=severity,
                line=_node_line(node),
                col=_node_col(node),
                message=message,
                suggestion=suggestion,
            )
        )

    # ── Imports ──────────────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self._imports[local] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self._import_froms[local] = f"{module}.{alias.name}"
        self.generic_visit(node)

    # ── Function-level checks ─────────────────────────────────────────────────

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        name = node.name
        lines = _func_source_lines(node)
        params = len(node.args.args) + len(node.args.posonlyargs) + len(node.args.kwonlyargs)

        if lines > MAX_FUNCTION_LINES:
            self._add(
                "CODE_SMELL", "long_function", "medium", node,
                f"Function '{name}' spans {lines} lines (limit {MAX_FUNCTION_LINES}).",
                "Break it into smaller, single-responsibility functions.",
            )

        if params > MAX_FUNCTION_PARAMS:
            self._add(
                "CODE_SMELL", "too_many_params", "medium", node,
                f"Function '{name}' has {params} parameters (limit {MAX_FUNCTION_PARAMS}).",
                "Group related parameters into a dataclass or config object.",
            )

        depth = _nesting_depth(node)
        if depth > MAX_NESTING_DEPTH:
            self._add(
                "CODE_SMELL", "deep_nesting", "medium", node,
                f"Function '{name}' has nesting depth {depth} (limit {MAX_NESTING_DEPTH}).",
                "Use early returns / guard clauses or extract inner blocks into helper functions.",
            )

        cc = _cognitive_complexity(node)
        if cc > MAX_COGNITIVE_COMPLEXITY:
            self._add(
                "CODE_SMELL", "high_complexity", "high", node,
                f"Function '{name}' has estimated cognitive complexity {cc} (limit {MAX_COGNITIVE_COMPLEXITY}).",
                "Decompose into smaller functions; reduce branching depth.",
            )

        # Missing return annotation
        if node.returns is None and name != "__init__":
            self._add(
                "CODE_SMELL", "missing_return_annotation", "info", node,
                f"Function '{name}' is missing a return type annotation.",
                "Add a return type: def {name}(...) -> ReturnType:",
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._check_function(node)
        self.generic_visit(node)

    # ── Security checks ───────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func = node.func

        # eval() / exec() calls
        if isinstance(func, ast.Name) and func.id in ("eval", "exec"):
            self._add(
                "SECURITY", "eval_exec_usage", "critical", node,
                f"Call to '{func.id}()' found. Executing user-controlled strings is dangerous.",
                "Replace with a safer alternative (AST eval for math, explicit dispatch, etc.).",
            )

        # os.system / os.popen
        if isinstance(func, ast.Attribute):
            full = _get_full_attr(func)
            if full in ("os.system", "os.popen", "os.execv", "os.execve"):
                self._add(
                    "SECURITY", "os_shell_execution", "high", node,
                    f"Call to '{full}()' can execute arbitrary shell commands.",
                    "Use subprocess with a list argument (not shell=True) and validate inputs.",
                )

            # subprocess.run/Popen/call with shell=True
            if full in (
                "subprocess.run", "subprocess.Popen", "subprocess.call",
                "subprocess.check_call", "subprocess.check_output",
            ):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self._add(
                            "SECURITY", "subprocess_shell_true", "high", node,
                            f"'{full}(shell=True)' passes the command through the shell, enabling injection.",
                            "Pass a list instead of a string and remove shell=True.",
                        )

            # Weak hashing
            if isinstance(func.value, ast.Name) and func.value.id == "hashlib":
                if func.attr in _WEAK_HASH_NAMES:
                    self._add(
                        "SECURITY", "weak_hash_algorithm", "high", node,
                        f"hashlib.{func.attr}() uses a weak/broken hash algorithm.",
                        "Use hashlib.sha256() or better. For passwords, use bcrypt/argon2.",
                    )

            # pickle.loads
            if full in ("pickle.loads", "pickle.load"):
                self._add(
                    "SECURITY", "unsafe_deserialization", "high", node,
                    f"'{full}()' deserializes untrusted data and can execute arbitrary code.",
                    "Avoid pickle for untrusted input. Use json, msgpack, or protobuf instead.",
                )

            # random used in security context heuristic: variable name contains token/key/secret
            if isinstance(func.value, ast.Name) and func.value.id == "random":
                if func.attr in _INSECURE_RANDOM_NAMES:
                    self._add(
                        "SECURITY", "insecure_random", "medium", node,
                        "random module is not cryptographically secure.",
                        "Use secrets.token_hex() / secrets.choice() for security-sensitive randomness.",
                    )

        # assert used for validation
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:  # noqa: N802
        self._add(
            "SECURITY", "assert_used_for_validation", "medium", node,
            "assert statements are stripped when Python runs with -O (optimized mode).",
            "Replace with explicit if/raise or use pydantic/cerberus validation.",
        )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        # Hardcoded secret detection: look for name = "literal"
        for target in node.targets:
            if isinstance(target, ast.Name) and _SECRET_KEY_PATTERN.search(target.id):
                if _is_string_const(node.value):
                    raw = repr(node.value.value)
                    if _TRIVIAL_SECRET_VALUE.match(raw):
                        self._add(
                            "SECURITY", "hardcoded_secret", "critical", node,
                            f"Variable '{target.id}' appears to contain a hardcoded secret.",
                            "Store secrets in environment variables or a secrets manager (e.g. python-dotenv, AWS Secrets Manager).",
                        )
            # Track assignments for unused-variable detection
            if isinstance(target, ast.Name):
                self._assigned_names.add(target.id)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if isinstance(node.ctx, ast.Load):
            self._used_names.add(node.id)
        self.generic_visit(node)

    # ── Performance checks ────────────────────────────────────────────────────

    def visit_For(self, node: ast.For) -> None:  # noqa: N802
        # Nested loop detection
        for child in ast.walk(node):
            if child is node:
                continue
            if isinstance(child, (ast.For, ast.While)):
                self._add(
                    "PERFORMANCE", "nested_loop", "medium", node,
                    "Nested loop detected — potential O(n²) or worse complexity.",
                    "Consider vectorisation (numpy), dict/set lookups, or algorithmic restructuring.",
                )
                break  # one finding per outer loop is enough

        # String concatenation in loop body
        for child in ast.walk(node):
            if isinstance(child, ast.AugAssign):
                if isinstance(child.op, ast.Add) and isinstance(child.target, ast.Name):
                    # Heuristic: if the RHS includes a Str/Name, flag it
                    self._add(
                        "PERFORMANCE", "string_concat_in_loop", "medium", child,
                        f"String concatenation with '+=' inside a loop creates O(n²) copies.",
                        "Collect parts in a list and join at the end: ''.join(parts).",
                    )
                    break

        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:  # noqa: N802
        # Nested loop inside while
        for child in ast.walk(node):
            if child is node:
                continue
            if isinstance(child, (ast.For, ast.While)):
                self._add(
                    "PERFORMANCE", "nested_loop", "medium", node,
                    "Nested loop detected — potential O(n²) or worse complexity.",
                    "Consider vectorisation (numpy), dict/set lookups, or algorithmic restructuring.",
                )
                break
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:  # noqa: N802
        # Deeply nested comprehension
        if len(node.generators) > 2:
            self._add(
                "CODE_SMELL", "complex_comprehension", "low", node,
                f"List comprehension has {len(node.generators)} generators — hard to read.",
                "Replace with an explicit for-loop with named variables.",
            )
        self.generic_visit(node)

    # ── Magic numbers ─────────────────────────────────────────────────────────

    def visit_Constant(self, node: ast.Constant) -> None:  # noqa: N802
        if isinstance(node.value, (int, float)):
            # Ignore 0, 1, -1, 2 — these are conventionally acceptable
            if node.value not in (0, 1, -1, 2, 0.0, 1.0, -1.0, 100):
                # Only flag when the constant appears as a standalone expression
                # or in a binary op, not in slice/range (too noisy)
                # We'll check parent context via a separate pass below.
                pass
        self.generic_visit(node)

    # ── Post-visit: unused variables ─────────────────────────────────────────

    def finalize(self) -> None:
        """Run checks that need full-tree information."""
        potentially_unused = self._assigned_names - self._used_names
        # Filter out _ prefixed (intentionally unused by convention)
        for name in potentially_unused:
            if not name.startswith("_") and name not in ("self", "cls"):
                # We don't have line info here — emit without line
                self.findings.append(
                    Finding(
                        category="CODE_SMELL",
                        rule_id="unused_variable",
                        severity="low",
                        line=None,
                        col=None,
                        message=f"Variable '{name}' is assigned but never read.",
                        suggestion="Remove the assignment or prefix with '_' if intentionally unused.",
                    )
                )


# ─── Magic-number second pass ─────────────────────────────────────────────────

class _MagicNumberVisitor(ast.NodeVisitor):
    """Separate pass to detect magic numbers in expressions (not in slices/ranges)."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self._in_range = False
        self._in_slice = False

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        if isinstance(node.func, ast.Name) and node.func.id == "range":
            old = self._in_range
            self._in_range = True
            self.generic_visit(node)
            self._in_range = old
            return
        self.generic_visit(node)

    def visit_Slice(self, node: ast.Slice) -> None:  # noqa: N802
        old = self._in_slice
        self._in_slice = True
        self.generic_visit(node)
        self._in_slice = old

    def visit_Constant(self, node: ast.Constant) -> None:  # noqa: N802
        if self._in_range or self._in_slice:
            return
        if isinstance(node.value, (int, float)) and node.value not in (
            0, 1, -1, 2, 0.0, 1.0, -1.0, 100, 10, 1000,
        ):
            self.findings.append(
                Finding(
                    category="CODE_SMELL",
                    rule_id="magic_number",
                    severity="info",
                    line=_node_line(node),
                    col=_node_col(node),
                    message=f"Magic number {node.value!r} found in expression.",
                    suggestion="Extract into a named constant: MAX_RETRIES = 5.",
                )
            )
        self.generic_visit(node)


# ─── Duplicate code smell (token-level) ──────────────────────────────────────

def _detect_duplicate_blocks(source: str, min_lines: int = 6) -> list[Finding]:
    """
    Sliding-window duplicate detection on non-blank, non-comment lines.
    Flags blocks of >=min_lines consecutive lines that appear more than once.
    This is intentionally simple — a production tool would use suffix arrays.
    """
    findings: list[Finding] = []
    lines = [ln.strip() for ln in source.splitlines()]
    non_trivial = [
        (i + 1, ln) for i, ln in enumerate(lines)
        if ln and not ln.startswith("#")
    ]
    seen: dict[tuple, int] = {}
    for start_idx in range(len(non_trivial) - min_lines + 1):
        window = tuple(ln for _, ln in non_trivial[start_idx: start_idx + min_lines])
        line_no = non_trivial[start_idx][0]
        if window in seen:
            findings.append(
                Finding(
                    category="CODE_SMELL",
                    rule_id="duplicate_code_block",
                    severity="medium",
                    line=line_no,
                    col=None,
                    message=(
                        f"Code block starting at line {line_no} appears to duplicate "
                        f"a block near line {seen[window]}."
                    ),
                    suggestion="Extract the repeated logic into a shared function.",
                )
            )
        else:
            seen[window] = line_no
    return findings


# ─── Public entry point ───────────────────────────────────────────────────────

def analyze(source: str) -> AnalysisResult:
    """
    Analyze *source* (a string of Python code) and return an AnalysisResult.
    Never raises — all errors are captured in AnalysisResult.error.
    """
    if not source or not source.strip():
        return AnalysisResult(ok=False, error="Source code is empty.")

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return AnalysisResult(
            ok=False,
            error=f"SyntaxError at line {exc.lineno}: {exc.msg}",
        )
    except Exception as exc:  # noqa: BLE001
        return AnalysisResult(ok=False, error=f"Parse error: {exc}")

    source_lines = source.splitlines()

    # Main visitor
    visitor = _VibeGuardVisitor(source_lines)
    visitor.visit(tree)
    visitor.finalize()

    # Magic numbers
    mn_visitor = _MagicNumberVisitor()
    mn_visitor.visit(tree)

    # Duplicate blocks
    dup_findings = _detect_duplicate_blocks(source)

    all_findings = visitor.findings + mn_visitor.findings + dup_findings

    # Deduplicate identical (rule_id, line) pairs
    seen_keys: set[tuple] = set()
    unique: list[Finding] = []
    for f in all_findings:
        key = (f.rule_id, f.line, f.message[:40])
        if key not in seen_keys:
            seen_keys.add(key)
            unique.append(f)

    # Sort: severity order then line number
    severity_order = {s: i for i, s in enumerate(SEVERITIES)}
    unique.sort(key=lambda f: (severity_order.get(f.severity, 99), f.line or 0))

    return AnalysisResult(ok=True, findings=unique)
