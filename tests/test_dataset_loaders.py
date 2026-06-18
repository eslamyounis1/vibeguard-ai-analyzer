import json

import pytest

from corpus.loaders.evalplus import load_evalplus
from corpus.loaders.securityeval import load_securityeval


def test_load_securityeval_normalises_cwe(tmp_path):
    path = tmp_path / "securityeval.jsonl"
    path.write_text(json.dumps({
        "ID": "CWE-020_author_1.py",
        "Prompt": "def parse(value): ...",
        "Insecure_code": "def parse(value):\n    return value",
    }) + "\n", encoding="utf-8")

    sample = load_securityeval(path)[0]
    assert sample.expected_security_labels == ["CWE-20"]
    assert sample.source == "securityeval"


def test_load_evalplus_official_jsonl(tmp_path):
    path = tmp_path / "HumanEvalPlus-v0.1.10.jsonl"
    path.write_text(json.dumps({
        "task_id": "HumanEval/0",
        "prompt": "def add(a, b):\n",
        "canonical_solution": "    return a + b\n",
        "entry_point": "add",
    }) + "\n", encoding="utf-8")

    sample = load_evalplus(tmp_path, subsets=("humanevalplus",))[0]
    assert sample.code == "def add(a, b):\n    return a + b\n"
    assert sample.entry_point == "add"
    assert sample.metadata["subset"] == "humanevalplus"


def test_load_evalplus_file_rejects_incompatible_subset(tmp_path):
    path = tmp_path / "HumanEvalPlus-v0.1.10.jsonl"
    path.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="only supports"):
        load_evalplus(path, subsets=("mbppplus",))
