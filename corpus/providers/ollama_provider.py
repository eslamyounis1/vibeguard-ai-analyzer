from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from corpus.providers.base import Provider

_DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


class OllamaProvider(Provider):
    """Local open-model generation via the Ollama HTTP API (no paid keys)."""

    name = "ollama"

    def __init__(self, model: str = "gemma:e2b", host: str = _DEFAULT_HOST, **kwargs):
        super().__init__(model=model, **kwargs)
        self.host = host.rstrip("/")

    @classmethod
    def available(cls) -> bool:
        try:
            with urllib.request.urlopen(f"{_DEFAULT_HOST}/api/tags", timeout=1):
                return True
        except Exception:
            return False

    def _complete(self, prompt: str) -> str:
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": self.temperature},
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                return json.loads(response.read().decode("utf-8")).get("response", "")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                detail = json.loads(body).get("error", body)
            except json.JSONDecodeError:
                detail = body or exc.reason
            raise RuntimeError(
                f"Ollama HTTP {exc.code} for model {self.model!r}: {detail}. "
                "Run `ollama list` and pass the exact tag, e.g. "
                "`--generate ollama:gemma4:e2b`."
            ) from exc
