import os
from pathlib import Path
from typing import List

_SKIP_DIRS = frozenset({
    ".venv", "venv", "env", ".env",
    ".git", "__pycache__", ".mypy_cache", ".pytest_cache",
    "node_modules", "dist", "build", ".tox", "site-packages",
})


def collect_python_files(path: str) -> List[str]:
    p = Path(path)
    if p.is_file():
        return [str(p)] if p.suffix == ".py" else []
    if p.is_dir():
        found = []
        for root, dirs, filenames in os.walk(p):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for name in filenames:
                if name.endswith(".py"):
                    found.append(os.path.join(root, name))
        return sorted(found)
    return []
