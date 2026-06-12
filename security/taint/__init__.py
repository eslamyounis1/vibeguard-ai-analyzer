"""Lightweight AST-based taint analysis for VibeGuard (W6)."""

from security.taint.tracer import TaintPath, TaintTracer, trace_taint

__all__ = ["TaintPath", "TaintTracer", "trace_taint"]
