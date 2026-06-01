"""Build a study corpus: load public datasets and/or generate AI solutions.

Examples:
    # CWEval secure references (25 Python security tasks)
    python -m corpus.build --datasets cweval --out data/corpus/cweval_ref.jsonl

    # Generate AI solutions for CWEval tasks
    python -m corpus.build --datasets cweval \\
        --generate openai:gpt-4o-mini ollama:llama3.2 \\
        --out data/corpus/cweval_ai.jsonl

    # Offline: in-repo security ground truth + HumanEval references
    python -m corpus.build --datasets security humaneval --out data/corpus/corpus.jsonl
"""

from __future__ import annotations

import argparse
from typing import List, Optional

from corpus.cweval_prompt import make_generation_prompt
from corpus.loaders import (
    load_cweval,
    load_cweval_synthetic_insecure,
    load_evalplus,
    load_humaneval,
    load_mbpp,
    load_sallm,
    load_secodeplt,
    load_security_benchmark,
)
from corpus.providers import get_provider
from corpus.schema import CorpusSample, write_corpus

_TASK_DATASETS = {"humaneval", "mbpp", "cweval", "evalplus"}


def _parse_provider_spec(spec: str) -> tuple[str, str]:
    """Parse ``provider:model``; model may contain colons (e.g. ``ollama:gemma:e2b``)."""
    parts = spec.split(":", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(
            f"Invalid provider spec {spec!r}. Use provider:model, e.g. ollama:gemma:e2b"
        )
    return parts[0], parts[1]


def _load_dataset(
    name: str,
    limit,
    cweval_path: Optional[str],
    evalplus_path: Optional[str] = None,
    sallm_path: Optional[str] = None,
    secodeplt_path: Optional[str] = None,
) -> List[CorpusSample]:
    if name == "humaneval":
        return load_humaneval(limit)
    if name == "mbpp":
        return load_mbpp(limit)
    if name == "security":
        return load_security_benchmark()
    if name == "evalplus":
        root = evalplus_path or "dataset/evalplus"
        return load_evalplus(root=root, limit=limit)
    if name == "sallm":
        path = sallm_path or "dataset/sallm/dataset.jsonl"
        return load_sallm(path=path, limit=limit)
    if name == "secodeplt":
        root = secodeplt_path or "dataset/secodeplt"
        return load_secodeplt(root=root, limit=limit)
    if name == "cweval":
        root = cweval_path or "dataset/cweval/benchmark/core/py"
        return load_cweval(root=root, limit=limit)
    if name == "cweval-synthetic":
        root = cweval_path or "dataset/cweval/benchmark/core/py"
        refs = {s.task_id: s for s in load_cweval(root=root, limit=limit)}
        samples = load_cweval_synthetic_insecure(root=root, limit=limit)
        for s in samples:
            ref = refs.get(s.task_id)
            if ref:
                s.prompt = ref.prompt
        return samples
    raise ValueError(f"Unknown dataset: {name!r}")


def _build_prompt(sample: CorpusSample) -> str:
    if "cweval" in sample.tags:
        return make_generation_prompt(sample.prompt)
    return (
        "Complete the following Python task. Respond with only the Python code, "
        "no explanation.\n\n" + sample.prompt
    )


def build_corpus(
    datasets,
    generate,
    limit,
    cache_dir,
    out,
    cweval_path: Optional[str] = None,
    evalplus_path: Optional[str] = None,
    sallm_path: Optional[str] = None,
    secodeplt_path: Optional[str] = None,
) -> int:
    samples: List[CorpusSample] = []
    task_samples: List[CorpusSample] = []

    for name in datasets:
        loaded = _load_dataset(
            name, limit, cweval_path, evalplus_path, sallm_path, secodeplt_path
        )
        samples.extend(loaded)
        if name in _TASK_DATASETS:
            task_samples.extend(loaded)

    for spec in generate or []:
        provider_name, model = _parse_provider_spec(spec)
        provider = get_provider(provider_name, model=model, cache_dir=cache_dir)
        for task in task_samples:
            code = provider.generate(_build_prompt(task))
            meta = dict(task.metadata)
            meta["generated_for"] = task.id
            meta["provider"] = f"{provider.name}:{provider.model}"
            samples.append(
                CorpusSample(
                    id=f"{task.task_id}::{provider.name}:{provider.model}",
                    task_id=task.task_id,
                    source=f"{provider.name}:{provider.model}",
                    prompt=task.prompt,
                    code=code,
                    reference_solution=task.reference_solution,
                    tests=task.tests,
                    entry_point=task.entry_point,
                    expected_security_labels=list(task.expected_security_labels),
                    tags=["ai-generated"] + [t for t in task.tags if t != "reference"],
                    metadata=meta,
                )
            )

    return write_corpus(samples, out)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the VibeGuard study corpus.")
    parser.add_argument(
        "--datasets", nargs="+", default=["security"],
        help=(
            "Datasets to load: security, humaneval, mbpp, cweval, cweval-synthetic, "
            "evalplus, sallm, secodeplt."
        ),
    )
    parser.add_argument(
        "--generate", nargs="*", default=[],
        help="Provider specs: provider:model (e.g. openai:gpt-4o-mini ollama:gemma4:e2b).",
    )
    parser.add_argument("--limit", type=int, default=None, help="Limit task datasets to N samples.")
    parser.add_argument(
        "--cweval-path",
        default=None,
        help="Path to CWEval Python tasks (default: dataset/cweval/benchmark/core/py).",
    )
    parser.add_argument(
        "--evalplus-path",
        default=None,
        help="Path to EvalPlus root (default: dataset/evalplus).",
    )
    parser.add_argument(
        "--sallm-path",
        default=None,
        help="Path to SALLM dataset.jsonl (default: dataset/sallm/dataset.jsonl).",
    )
    parser.add_argument(
        "--secodeplt-path",
        default=None,
        help="Path to SeCodePLT root (default: dataset/secodeplt).",
    )
    parser.add_argument("--cache-dir", default="data/cache", help="LLM response cache directory.")
    parser.add_argument("--out", default="data/corpus/corpus.jsonl", help="Output JSONL path.")
    args = parser.parse_args()

    count = build_corpus(
        datasets=args.datasets,
        generate=args.generate,
        limit=args.limit,
        cache_dir=args.cache_dir,
        out=args.out,
        cweval_path=args.cweval_path,
        evalplus_path=args.evalplus_path,
        sallm_path=args.sallm_path,
        secodeplt_path=args.secodeplt_path,
    )
    print(f"Wrote {count} sample(s) to {args.out}")


if __name__ == "__main__":
    main()
