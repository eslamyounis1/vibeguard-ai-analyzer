import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_NONE_ALGORITHMS = frozenset({"none", "None", "NONE"})


class JwtNoVerifyRule(SecurityRule):
    rule_id = "jwt_signature_not_verified"
    title = "JWT Signature Not Verified (CWE-347)"
    description = "JWT decoded without signature verification allows token forgery."
    severity = Severity.CRITICAL

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if self._is_jwt_decode_without_verify(node):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="JWT decoded without signature verification (verify=False or algorithms=['none']).",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Always verify JWT signatures: jwt.decode(token, key, algorithms=['HS256']) with options={'verify_signature': True}.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _is_jwt_decode_without_verify(self, node: ast.Call) -> bool:
        func = node.func
        is_decode = (
            (isinstance(func, ast.Attribute) and func.attr == "decode") or
            (isinstance(func, ast.Name) and func.id == "decode")
        )
        if not is_decode:
            return False

        # Check for verify=False
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return True
            if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                for k, v in zip(kw.value.keys, kw.value.values):
                    if (isinstance(k, ast.Constant) and "verify" in str(k.value) and
                            isinstance(v, ast.Constant) and v.value is False):
                        return True

        # Check for algorithms=['none']
        for kw in node.keywords:
            if kw.arg == "algorithms":
                alg_node = kw.value
                if isinstance(alg_node, (ast.List, ast.Tuple)):
                    for elt in alg_node.elts:
                        if isinstance(elt, ast.Constant) and str(elt.value).lower() == "none":
                            return True
        for arg in node.args:
            if isinstance(arg, (ast.List, ast.Tuple)):
                for elt in arg.elts:
                    if isinstance(elt, ast.Constant) and str(elt.value).lower() == "none":
                        return True

        return False
