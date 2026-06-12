"""Lightweight AST-based taint tracker (W6).

Taint-lite reduces SSRF/XSS false negatives without requiring a full
data-flow framework. It tracks parameter → sink paths within a single function.

Sources:   function parameters (any param of the target function)
Propagation: assignment, f-string interpolation, string concat (+), dict access
Sinks:     requests.get/post, urllib.urlopen, Response()/make_response(),
           render_template_string(), logging calls

Output: list[TaintPath] — each path shows source_param → sink_call.

Paper claim: "Taint-lite reduces SSRF/XSS false negatives without requiring a
full data-flow framework."
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Sink definitions
# ---------------------------------------------------------------------------

_SSRF_SINKS: frozenset[str] = frozenset({
    "get", "post", "put", "patch", "delete", "head", "request", "urlopen",
})

_XSS_SINKS: frozenset[str] = frozenset({
    "Response", "make_response", "render_template_string", "Markup", "mark_safe",
})

_LOG_SINKS: frozenset[str] = frozenset({
    "debug", "info", "warning", "error", "critical", "exception", "log",
})

ALL_SINKS: frozenset[str] = _SSRF_SINKS | _XSS_SINKS | _LOG_SINKS


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class TaintPath:
    """A single source-to-sink taint path found within a function."""
    source_param: str          # Parameter name (taint source)
    sink_call: str             # Sink function/method name
    sink_lineno: int           # Line of the sink call
    path_nodes: List[str] = field(default_factory=list)  # Intermediate variables
    sink_category: str = ""    # "ssrf" | "xss" | "log" | "other"

    def __str__(self) -> str:
        chain = " -> ".join([self.source_param] + self.path_nodes + [self.sink_call])
        return f"line {self.sink_lineno}: {chain} ({self.sink_category})"


# ---------------------------------------------------------------------------
# Taint visitor
# ---------------------------------------------------------------------------

class _TaintVisitor(ast.NodeVisitor):
    """Visits a function body and tracks taint from parameters to sinks."""

    def __init__(self, params: Set[str]) -> None:
        self.tainted: Set[str] = set(params)
        self.paths: List[TaintPath] = []
        self._assignments: Dict[str, str] = {}  # var -> source_param

    # --- Propagation via assignment ---

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._is_tainted_expr(node.value):
            source = self._taint_source(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)
                    if source:
                        self._assignments[target.id] = source
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value and self._is_tainted_expr(node.value):
            source = self._taint_source(node.value)
            if isinstance(node.target, ast.Name):
                self.tainted.add(node.target.id)
                if source:
                    self._assignments[node.target.id] = source
        self.generic_visit(node)

    # --- Sink detection ---

    def visit_Call(self, node: ast.Call) -> None:
        sink_name = self._sink_name(node)
        if sink_name and self._call_has_tainted_arg(node):
            source = self._find_taint_source_for_call(node)
            path_nodes = []
            # Build a brief chain if we have assignment info
            for arg in _iter_call_args(node):
                if isinstance(arg, ast.Name) and arg.id in self._assignments:
                    path_nodes = [arg.id]
                    source = source or self._assignments[arg.id]
                elif isinstance(arg, ast.Name) and arg.id in self.tainted:
                    path_nodes = [arg.id]
                    source = source or arg.id

            if source is None:
                source = "<unknown>"

            category = self._classify_sink(sink_name)
            self.paths.append(TaintPath(
                source_param=source,
                sink_call=sink_name,
                sink_lineno=node.lineno,
                path_nodes=path_nodes,
                sink_category=category,
            ))
        self.generic_visit(node)

    # --- Helpers ---

    def _is_tainted_expr(self, node: ast.expr) -> bool:
        """Return True if node contains a tainted name."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.JoinedStr):  # f-string
            return any(
                self._is_tainted_expr(v.value)
                for v in ast.walk(node)
                if isinstance(v, ast.FormattedValue)
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._is_tainted_expr(node.left) or self._is_tainted_expr(node.right)
        if isinstance(node, ast.Subscript):  # dict[key] access
            return self._is_tainted_expr(node.value) or self._is_tainted_expr(node.slice)
        if isinstance(node, ast.Attribute):
            return self._is_tainted_expr(node.value)
        if isinstance(node, ast.Call):
            # Taint flows from args into the call result
            if any(self._is_tainted_expr(a) for a in _iter_call_args(node)):
                return True
            # Taint propagates through method chains: obj.method() where obj is tainted
            if isinstance(node.func, ast.Attribute) and self._is_tainted_expr(node.func.value):
                return True
        return False

    def _taint_source(self, node: ast.expr) -> Optional[str]:
        """Return the first tainted parameter name flowing into node."""
        if isinstance(node, ast.Name) and node.id in self.tainted:
            return self._assignments.get(node.id, node.id)
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted:
                return self._assignments.get(child.id, child.id)
        return None

    def _sink_name(self, node: ast.Call) -> Optional[str]:
        func = node.func
        if isinstance(func, ast.Attribute):
            return func.attr if func.attr in ALL_SINKS else None
        if isinstance(func, ast.Name):
            return func.id if func.id in ALL_SINKS else None
        return None

    def _call_has_tainted_arg(self, node: ast.Call) -> bool:
        for arg in _iter_call_args(node):
            if self._is_tainted_expr(arg):
                return True
        return False

    def _find_taint_source_for_call(self, node: ast.Call) -> Optional[str]:
        for arg in _iter_call_args(node):
            src = self._taint_source(arg)
            if src:
                return src
        return None

    def _classify_sink(self, name: str) -> str:
        if name in _SSRF_SINKS:
            return "ssrf"
        if name in _XSS_SINKS:
            return "xss"
        if name in _LOG_SINKS:
            return "log"
        return "other"


def _iter_call_args(node: ast.Call):
    """Yield all positional and keyword value args."""
    yield from node.args
    for kw in node.keywords:
        yield kw.value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class TaintTracer:
    """Run taint analysis on a parsed AST."""

    def trace_function(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> List[TaintPath]:
        """Trace taint from *func_node*'s parameters to sinks in its body."""
        params: Set[str] = set()
        for arg in func_node.args.args:
            params.add(arg.arg)
        for arg in func_node.args.posonlyargs:
            params.add(arg.arg)
        for arg in func_node.args.kwonlyargs:
            params.add(arg.arg)
        if func_node.args.vararg:
            params.add(func_node.args.vararg.arg)
        if func_node.args.kwarg:
            params.add(func_node.args.kwarg.arg)

        if not params:
            return []

        visitor = _TaintVisitor(params)
        for stmt in func_node.body:
            visitor.visit(stmt)
        return visitor.paths

    def trace_all_functions(self, tree: ast.AST) -> Dict[str, List[TaintPath]]:
        """Trace taint in every function in the module. Returns {func_name: paths}."""
        results: Dict[str, List[TaintPath]] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                paths = self.trace_function(node)
                if paths:
                    results[node.name] = paths
        return results


def trace_taint(
    source_code: str,
    sink_categories: Optional[List[str]] = None,
) -> List[TaintPath]:
    """Parse *source_code* and return all taint paths, optionally filtered by category.

    Args:
        source_code: Python source to analyse.
        sink_categories: Optional list of categories to filter (e.g. ["ssrf", "xss"]).

    Returns:
        List of TaintPath instances found in the code.
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return []

    tracer = TaintTracer()
    all_paths: List[TaintPath] = []
    for paths in tracer.trace_all_functions(tree).values():
        all_paths.extend(paths)

    if sink_categories:
        cats = set(sink_categories)
        all_paths = [p for p in all_paths if p.sink_category in cats]

    return all_paths
