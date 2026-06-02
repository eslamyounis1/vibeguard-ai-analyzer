"""LLM provider registry and factory."""

from __future__ import annotations

from typing import Dict, List, Type

from corpus.providers.anthropic_provider import AnthropicProvider
from corpus.providers.base import Provider, extract_code
from corpus.providers.ollama_provider import OllamaProvider
from corpus.providers.openai_provider import OpenAIProvider

_PROVIDERS: Dict[str, Type[Provider]] = {
    OpenAIProvider.name: OpenAIProvider,
    AnthropicProvider.name: AnthropicProvider,
    OllamaProvider.name: OllamaProvider,
}


def get_provider(name: str, **kwargs) -> Provider:
    cls = _PROVIDERS.get(name)
    if cls is None:
        raise ValueError(f"Unknown provider: {name!r}. Known: {sorted(_PROVIDERS)}")
    return cls(**kwargs)


def available_providers() -> List[str]:
    return [name for name, cls in _PROVIDERS.items() if cls.available()]


__all__ = [
    "Provider",
    "extract_code",
    "OpenAIProvider",
    "AnthropicProvider",
    "OllamaProvider",
    "get_provider",
    "available_providers",
]
