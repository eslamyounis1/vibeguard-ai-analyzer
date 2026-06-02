from __future__ import annotations

import os

from corpus.providers.base import Provider


class OpenAIProvider(Provider):
    name = "openai"

    def __init__(self, model: str = "gpt-4o-mini", **kwargs):
        super().__init__(model=model, **kwargs)

    @classmethod
    def available(cls) -> bool:
        try:
            import openai  # noqa: F401
        except Exception:
            return False
        return bool(os.environ.get("OPENAI_API_KEY"))

    def _complete(self, prompt: str) -> str:
        from openai import OpenAI

        client = OpenAI()
        response = client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content or ""
