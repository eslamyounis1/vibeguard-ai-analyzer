#!/usr/bin/env bash
# Reproduce the oracle annotations and publication tables from a cached or new corpus.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PYTHON="${PYTHON:-${REPO_ROOT}/.venv/bin/python}"
CORPUS="${CORPUS:-data/corpus/cweval_repeated_openai.jsonl}"
ANNOTATED="${ANNOTATED:-data/corpus/cweval_repeated_openai_annotated.jsonl}"
RESULTS_DIR="${RESULTS_DIR:-results/research_v4}"
BOOTSTRAP_ITERATIONS="${BOOTSTRAP_ITERATIONS:-5000}"

MODELS=(
  openai:gpt-4.1-2025-04-14
  openai:gpt-4.1-mini-2025-04-14
  openai:gpt-4o-2024-08-06
  openai:gpt-4o-mini-2024-07-18
)

[[ -x "${PYTHON}" ]] || {
  printf 'Python environment not found: %s\n' "${PYTHON}" >&2
  exit 1
}

if [[ ! -f "${CORPUS}" ]]; then
  [[ -n "${OPENAI_API_KEY:-}" ]] || {
    printf 'OPENAI_API_KEY is required to generate a missing corpus.\n' >&2
    exit 1
  }
  "${PYTHON}" -m corpus.build \
    --datasets cweval \
    --generate "${MODELS[@]}" \
    --samples-per-task 5 \
    --temperature 0.2 \
    --cache-dir data/cache \
    --out "${CORPUS}"
fi

if [[ ! -f "${ANNOTATED}" ]]; then
  "${PYTHON}" -m experiments.annotate_cweval \
    --corpus "${CORPUS}" \
    --out "${ANNOTATED}" \
    --workers "${ORACLE_WORKERS:-6}" \
    --timeout-seconds "${ORACLE_TIMEOUT_SECONDS:-30}"
fi

"${PYTHON}" -m experiments.run_research_evaluation \
  --corpus "${ANNOTATED}" \
  --evalplus-path dataset/evalplus \
  --out-dir "${RESULTS_DIR}" \
  --bootstrap-iterations "${BOOTSTRAP_ITERATIONS}"

if [[ "${WITH_LLM_REPAIR:-1}" == "1" ]]; then
  "${PYTHON}" -m experiments.run_llm_repair \
    --corpus "${ANNOTATED}" \
    --out-dir "${RESULTS_DIR}/repair" \
    --model gpt-4o-mini-2024-07-18 \
    --cache-dir data/cache
fi

printf 'Publication artifacts written to %s\n' "${RESULTS_DIR}"
