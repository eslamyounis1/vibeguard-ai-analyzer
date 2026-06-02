"""Provider abstraction for LLM code generation, with on-disk caching.

Caching is keyed by (provider, model, temperature, prompt) so that re-running
the corpus build is reproducible and does not re-bill API calls. The raw
response and the extracted code are both stored.
"""

from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from pathlib import Path

_FENCE = re.compile(r"```(?:python)?\s*\n(.*?)```", re.DOTALL)


def extract_code(text: str) -> str:
    """Pull the first fenced code block, or return the text as-is."""
    match = _FENCE.search(text)
    return (match.group(1) if match else text).strip()


class Provider(ABC):
    name: str = "base"

    def __init__(self, model: str, cache_dir: str | Path = "data/cache", temperature: float = 0.2):
        self.model = model
        self.temperature = temperature
        self.cache_dir = Path(cache_dir) / self.name

    @classmethod
    def available(cls) -> bool:
        return False

    @abstractmethod
    def _complete(self, prompt: str) -> str:
        ...

    def _cache_path(self, prompt: str) -> Path:
        key = hashlib.sha256(
            f"{self.name}|{self.model}|{self.temperature}|{prompt}".encode("utf-8")
        ).hexdigest()
        return self.cache_dir / f"{key}.json"

    def generate(self, prompt: str, use_cache: bool = True) -> str:
        cache_path = self._cache_path(prompt)
        if use_cache and cache_path.exists():
            return json.loads(cache_path.read_text(encoding="utf-8"))["code"]

        raw = self._complete(prompt)
        code = extract_code(raw)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(
            json.dumps(
                {"model": self.model, "prompt": prompt, "raw": raw, "code": code},
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return code
