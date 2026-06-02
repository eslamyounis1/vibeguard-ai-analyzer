from __future__ import annotations

import os

from corpus.providers.base import Provider


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, model: str = "claude-3-5-sonnet-latest", **kwargs):
        super().__init__(model=model, **kwargs)

    @classmethod
    def available(cls) -> bool:
        try:
            import anthropic  # noqa: F401
        except Exception:
            return False
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    def _complete(self, prompt: str) -> str:
        import anthropic

        client = anthropic.Anthropic()
        message = client.messages.create(
            model=self.model,
            max_tokens=2048,
            temperature=self.temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(
            block.text for block in message.content if getattr(block, "type", "") == "text"
        )
