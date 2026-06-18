"""Conservative placeholder for path-traversal remediation."""

from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer
from security.models.finding import Finding


class PathTraversalFixer(Fixer):
    """Decline generic rewrites that lack an application-specific trust root.

    Correct path confinement requires a known base directory, canonicalization,
    and a post-resolution containment check. Injecting an assumed ``BASE_DIR`` or
    using ``normpath`` alone is both behavior-changing and insecure.
    """

    rule_id = "path_traversal"

    def fix(
        self,
        tree: ast.AST,
        finding: Finding,
        source: str,
        line_offsets: List[int],
    ) -> Optional[Edit]:
        return None
