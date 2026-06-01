"""Tests for CWEval corpus loading, prompt extraction, and pytest runner."""

from pathlib import Path

import pytest

from corpus.build import build_corpus
from corpus.cweval_prompt import (
    extract_prompt,
    extract_reference,
    make_generation_prompt,
    parse_task_filename,
)
from corpus.loaders.cweval import load_cweval
from corpus.schema import read_corpus
from experiments.cwe_scoping import in_scope_cwe, supported_cwes
from experiments.cweval_runner import run_cweval_tests

CWEVAL_ROOT = Path("dataset/cweval/benchmark/core/py")
pytestmark = pytest.mark.skipif(
    not CWEVAL_ROOT.is_dir(),
    reason="CWEval dataset not downloaded (dataset/cweval/)",
)


class TestCWEvalPrompt:
    def test_extract_prompt_strips_solution(self):
        task = (CWEVAL_ROOT / "cwe_020_0_task.py").read_text(encoding="utf-8")
        prompt = extract_prompt(task)
        assert "# BEGIN SOLUTION" not in prompt
        assert "def get_target_for_redirect" in prompt
        assert "urlparse" not in prompt

    def test_extract_reference_includes_solution(self):
        task = (CWEVAL_ROOT / "cwe_020_0_task.py").read_text(encoding="utf-8")
        ref = extract_reference(task)
        assert "urlparse" in ref

    def test_parse_task_filename(self):
        stem, cwe, variant = parse_task_filename(CWEVAL_ROOT / "cwe_502_0_task.py")
        assert stem == "cwe_502_0"
        assert cwe == "CWE-502"
        assert variant == 0

    def test_make_generation_prompt_wraps_code(self):
        p = make_generation_prompt("def f(): pass")
        assert "```python" in p
        assert "def f(): pass" in p


class TestCWEvalLoader:
    def test_load_all_python_tasks(self):
        samples = load_cweval(limit=None)
        assert len(samples) == 25

    def test_sample_fields(self):
        samples = load_cweval(limit=1)
        s = samples[0]
        assert s.source == "human"
        assert s.expected_security_labels[0].startswith("CWE-")
        assert s.metadata.get("test_path")
        assert s.metadata.get("task_stem")
        assert "cweval" in s.tags

    def test_build_cweval_ref_jsonl(self, tmp_path):
        out = tmp_path / "cweval_ref.jsonl"
        count = build_corpus(
            datasets=["cweval"],
            generate=[],
            limit=3,
            cache_dir=tmp_path / "cache",
            out=out,
            cweval_path=str(CWEVAL_ROOT),
        )
        assert count == 3
        loaded = read_corpus(out)
        assert all(s.source == "human" for s in loaded)


class TestCWEvalRunner:
    def test_reference_passes_cwe_502(self):
        sample = load_cweval(root=CWEVAL_ROOT, limit=1)
        # find cwe_502_0
        samples = load_cweval(root=CWEVAL_ROOT)
        s502 = next(s for s in samples if s.task_id == "cwe_502_0")
        result = run_cweval_tests(
            s502.code,
            s502.metadata["task_stem"],
            s502.metadata["test_path"],
        )
        assert result.functional is True
        assert result.secure is True
        assert result.ok is True

    def test_unsafe_yaml_fails_security(self):
        unsafe = (
            "import json\nimport yaml\nfrom yaml import Loader\n\n"
            "def yaml_to_json(yaml_file_path: str) -> str:\n"
            "    with open(yaml_file_path, 'r') as file:\n"
            "        yaml_content = yaml.load(file, Loader=Loader)\n"
            "    return json.dumps(yaml_content)\n"
        )
        s502 = next(s for s in load_cweval(root=CWEVAL_ROOT) if s.task_id == "cwe_502_0")
        result = run_cweval_tests(
            unsafe,
            s502.metadata["task_stem"],
            s502.metadata["test_path"],
        )
        assert result.secure is False


class TestProviderSpec:
    def test_parse_model_with_colon(self):
        from corpus.build import _parse_provider_spec

        assert _parse_provider_spec("ollama:gemma:e2b") == ("ollama", "gemma:e2b")
        assert _parse_provider_spec("openai:gpt-4o-mini") == ("openai", "gpt-4o-mini")


class TestCWEScoping:
    def test_supported_cwes_non_empty(self):
        cwes = supported_cwes()
        assert "CWE-502" in cwes
        assert in_scope_cwe("CWE-502")
        assert not in_scope_cwe("CWE-020")
