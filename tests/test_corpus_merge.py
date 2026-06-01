import json
from pathlib import Path

import pytest

from corpus.merge import merge_corpora
from corpus.schema import CorpusSample, read_corpus


def _write(path: Path, rows):
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def test_merge_human_from_ref_skips_duplicate_human_in_ai_files(tmp_path):
    ref = tmp_path / "ref.jsonl"
    ai1 = tmp_path / "ai1.jsonl"
    ai2 = tmp_path / "ai2.jsonl"
    out = tmp_path / "multi.jsonl"

    _write(
        ref,
        [
            {"id": "h1", "task_id": "t1", "source": "human", "prompt": "p", "code": "c1"},
            {"id": "h2", "task_id": "t2", "source": "human", "prompt": "p", "code": "c2"},
        ],
    )
    _write(
        ai1,
        [
            {"id": "h1-dup", "task_id": "t1", "source": "human", "prompt": "p", "code": "wrong"},
            {"id": "g1", "task_id": "t1", "source": "openai:gpt-4o-mini", "prompt": "p", "code": "a1"},
        ],
    )
    _write(
        ai2,
        [
            {"id": "g2", "task_id": "t1", "source": "ollama:gemma4:e2b", "prompt": "p", "code": "a2"},
            {"id": "g3", "task_id": "t2", "source": "ollama:gemma4:e2b", "prompt": "p", "code": "a3"},
        ],
    )

    n = merge_corpora([ai1, ai2], out, human_from=ref)
    assert n == 5  # 2 human + 2 models on t1 + 1 gemma on t2
    samples = read_corpus(out)
    assert sum(1 for s in samples if s.source == "human") == 2
    assert samples[0].code == "c1"
    sources = {s.source for s in samples}
    assert sources == {"human", "openai:gpt-4o-mini", "ollama:gemma4:e2b"}


def test_merge_requires_human_source(tmp_path):
    ai = tmp_path / "ai.jsonl"
    empty = tmp_path / "empty.jsonl"
    _write(ai, [{"id": "g1", "task_id": "t1", "source": "openai:gpt-4o-mini", "prompt": "p", "code": "a"}])
    empty.write_text("\n")
    with pytest.raises(ValueError, match="No human"):
        merge_corpora([ai], tmp_path / "out.jsonl", human_from=empty)
