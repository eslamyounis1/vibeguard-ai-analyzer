from fixers import llm_fixer
from fixers.llm_fixer import llm_fix_source
from corpus.schema import CorpusSample
from experiments.run_llm_repair import _missing_llm_cache_entries, _summarise


def test_llm_gate_rejects_replacing_one_vulnerability_with_another(monkeypatch):
    original = "def run(user_input):\n    return eval(user_input)\n"
    replacement = "def run(user_input):\n    exec(user_input)\n"
    monkeypatch.setattr(llm_fixer, "_call_llm", lambda *args, **kwargs: replacement)

    result = llm_fix_source(original)

    assert result.safe is False
    assert result.changed is False
    assert "exec_usage" in (result.note or "")


def test_repair_cache_preflight_only_requires_entries_for_findings(tmp_path):
    clean = CorpusSample(
        id="clean", task_id="clean", source="model", prompt="", code="x = 1"
    )
    vulnerable = CorpusSample(
        id="vulnerable",
        task_id="vulnerable",
        source="model",
        prompt="",
        code="eval(user_input)",
    )

    assert _missing_llm_cache_entries(
        [clean, vulnerable], "model", str(tmp_path), use_cache=True
    ) == ["vulnerable"]


def test_repair_success_requires_functional_and_secure():
    rows = [
        {
            "task_id": "task-a",
            "repair_eligible": True,
            "det_repair_success": False,
            "llm_repair_success": True,
            "oracle_functional_before": True,
            "oracle_secure_before": False,
            "security_findings_before": 1,
            "det_changed": True,
            "det_findings_removed": 1,
            "det_functional_regression": True,
            "det_oracle_secure": False,
            "llm_changed": True,
            "llm_safe": True,
            "llm_findings_removed": 1,
            "llm_functional_regression": False,
            "llm_oracle_secure": True,
            "_model": "repair-model",
        }
    ]

    summary = _summarise(rows)
    assert summary["n_repair_eligible"] == 1
    assert summary["det_n_oracle_secure_improved"] == 0
    assert summary["llm_n_oracle_secure_improved"] == 1
    assert summary["det_functional_regressions"] == 1
    assert summary["det_eligible_functional_regressions"] == 1
    assert summary["llm_eligible_functional_regressions"] == 0
    assert summary["llm_oracle_secure_regressions"] == 0
    assert summary["n_repair_eligible_tasks"] == 1
    assert summary["llm_task_macro_success_rate"] == 1.0
