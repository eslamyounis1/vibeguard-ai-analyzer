#!/usr/bin/env bash
# Reproduce VibeGuard empirical study artifacts:
#   datasets (optional) → build corpora → merge → run_study → optional energy/baselines
#
# Typical usage (corpora already built, no LLM calls):
#   ./scripts/reproduce_study.sh --skip-generate
#
# Offline smoke (no API keys, synthetic insecure CWEval samples):
#   ./scripts/reproduce_study.sh --synthetic --limit 5
#
# Full pipeline from scratch (requires OPENAI_API_KEY + Ollama for real LLM runs):
#   ./scripts/reproduce_study.sh --download --generate
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Defaults (override via flags or env)
DATA_DIR="${DATA_DIR:-data/corpus}"
RESULTS_DIR="${RESULTS_DIR:-results/study_multi}"
ENERGY_DIR="${ENERGY_DIR:-results/energy}"
BASELINES_DIR="${BASELINES_DIR:-results/baselines_multi}"
CWEVAL_ROOT="${CWEVAL_ROOT:-dataset/cweval/benchmark/core/py}"

REF_CORPUS="${DATA_DIR}/cweval_ref.jsonl"
AI_CORPUS_GPT="${DATA_DIR}/cweval_ai.jsonl"
AI_CORPUS_GEMMA="${DATA_DIR}/cweval_gemma.jsonl"
SYNTHETIC_CORPUS="${DATA_DIR}/cweval_synthetic.jsonl"
MULTI_CORPUS="${DATA_DIR}/cweval_multi.jsonl"
EVALPLUS_CORPUS="${DATA_DIR}/evalplus.jsonl"

GPT_MODEL="${GPT_MODEL:-openai:gpt-4o-mini}"
GEMMA_MODEL="${GEMMA_MODEL:-ollama:gemma4:e2b}"

STUDY_RUNS="${STUDY_RUNS:-5}"
ENERGY_RUNS="${ENERGY_RUNS:-20}"
ENERGY_WARMUP="${ENERGY_WARMUP:-3}"
ENERGY_MAX_SAMPLES="${ENERGY_MAX_SAMPLES:-50}"
ENERGY_BACKEND="${ENERGY_BACKEND:-auto}"
LIMIT=""

limit_argv() {
  if [[ -n "${LIMIT}" ]]; then
    LIMIT_ARGV=(--limit "${LIMIT}")
  else
    LIMIT_ARGV=()
  fi
}

DO_DOWNLOAD=0
DO_DOWNLOAD_ALL=0
DO_GENERATE=0
USE_SYNTHETIC=0
SKIP_GENERATE=0
SKIP_STUDY=0
SKIP_ENERGY=1
WITH_ENERGY=0
WITH_BASELINES=0
WITH_DETECTION=0
WITH_LLM_REPAIR=0
WITH_SECURE_AT_K=0
FORCE=0
INSTALL_EXTRAS=0

usage() {
  cat <<'EOF'
Usage: scripts/reproduce_study.sh [OPTIONS]

Reproduce study artifacts under data/corpus/ and results/.

Corpus pipeline:
  --download          Clone CWEval + fetch EvalPlus from Hugging Face
  --download-all      Also fetch SeCodePLT and SALLM (large; optional for paper slice)
  --skip-generate     Reuse existing AI corpus files (default when not --generate/--synthetic)
  --generate          Call LLMs to build cweval_ai.jsonl and cweval_gemma.jsonl
  --synthetic         Offline mode: cweval-synthetic insecure samples (no API keys)
  --force             Rebuild corpora even if output files already exist

Study outputs:
  --skip-study        Only build/merge corpora; do not run experiments.run_study
  --out-dir DIR       Study output directory (default: results/study_multi)
  --with-energy       Also build EvalPlus corpus and run experiments.run_energy (RQ3)
  --energy-dir DIR    Energy output directory (default: results/energy)
  --with-baselines    Run experiments.run_baselines on merged AI corpus
  --baselines-dir DIR Baselines output (default: results/baselines_multi)
  --with-detection    Run cross-dataset detection study (SALLM + SecurityEval + EvalPlus)
  --with-llm-repair   Run LLM repair study (RQ4-B; requires OPENAI_API_KEY)
  --with-secure-at-k  Run secure@k / vulnerable@k metrics (RQ6)
  --limit N           Limit task samples (smoke tests)

Environment:
  OPENAI_API_KEY      Required for --generate with GPT
  GPT_MODEL           Default: openai:gpt-4o-mini
  GEMMA_MODEL         Default: ollama:gemma4:e2b (must match `ollama list`)
  DATA_DIR            Corpus directory (default: data/corpus)
  ENERGY_BACKEND      auto | rapl | linear_proxy | ...

Other:
  --install-extras    pip install -e ".[experiments]" before running
  -h, --help          Show this help
EOF
}

log() {
  printf '\n==> %s\n' "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

need_file() {
  [[ -f "$1" ]] || die "Missing required file: $1 (re-run without --skip-generate or pass --synthetic)"
}

maybe_skip() {
  local path="$1"
  if [[ "${FORCE}" -eq 0 && -f "${path}" ]]; then
    log "Skip (exists): ${path}"
    return 0
  fi
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --download) DO_DOWNLOAD=1; shift ;;
    --download-all) DO_DOWNLOAD=1; DO_DOWNLOAD_ALL=1; shift ;;
    --generate) DO_GENERATE=1; shift ;;
    --synthetic) USE_SYNTHETIC=1; shift ;;
    --skip-generate) SKIP_GENERATE=1; shift ;;
    --skip-study) SKIP_STUDY=1; shift ;;
    --with-energy) WITH_ENERGY=1; SKIP_ENERGY=0; shift ;;
    --skip-energy) WITH_ENERGY=0; SKIP_ENERGY=1; shift ;;
    --with-baselines) WITH_BASELINES=1; shift ;;
    --with-detection) WITH_DETECTION=1; shift ;;
    --with-llm-repair) WITH_LLM_REPAIR=1; shift ;;
    --with-secure-at-k) WITH_SECURE_AT_K=1; shift ;;
    --force) FORCE=1; shift ;;
    --install-extras) INSTALL_EXTRAS=1; shift ;;
    --out-dir) RESULTS_DIR="$2"; shift 2 ;;
    --energy-dir) ENERGY_DIR="$2"; shift 2 ;;
    --baselines-dir) BASELINES_DIR="$2"; shift 2 ;;
    --limit) LIMIT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (try --help)" ;;
  esac
done

if [[ "${DO_GENERATE}" -eq 1 && "${USE_SYNTHETIC}" -eq 1 ]]; then
  die "Use either --generate or --synthetic, not both"
fi

if [[ "${DO_GENERATE}" -eq 0 && "${USE_SYNTHETIC}" -eq 0 && "${SKIP_GENERATE}" -eq 0 ]]; then
  SKIP_GENERATE=1
fi

limit_argv

# Python: prefer repo venv
PYTHON="${PYTHON:-python3}"
if [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
  PYTHON="${REPO_ROOT}/.venv/bin/python"
fi

log "Repo root: ${REPO_ROOT}"
log "Python: ${PYTHON}"

if [[ "${INSTALL_EXTRAS}" -eq 1 ]]; then
  log "Installing package with experiments extras"
  "${PYTHON}" -m pip install -e ".[experiments]"
fi

"${PYTHON}" -c "import corpus, experiments" 2>/dev/null \
  || die "Import failed. Run: pip install -e \".[experiments]\" (or pass --install-extras)"

mkdir -p "${DATA_DIR}" "${RESULTS_DIR}"

# ---------------------------------------------------------------------------
# 1. Datasets (optional)
# ---------------------------------------------------------------------------
if [[ "${DO_DOWNLOAD}" -eq 1 ]]; then
  log "Downloading datasets"
  mkdir -p dataset

  if [[ ! -d dataset/cweval/.git ]]; then
    log "Cloning CWEval → dataset/cweval"
    git clone --depth 1 https://github.com/Co1lin/cweval.git dataset/cweval
  else
    log "CWEval already present: dataset/cweval"
  fi

  REPRO_DOWNLOAD_ALL="${DO_DOWNLOAD_ALL}" "${PYTHON}" - <<'PY'
import os
import sys

try:
    from huggingface_hub import snapshot_download
except ImportError:
    sys.exit("huggingface_hub not installed. Run: pip install huggingface_hub")

repos = [
    ("evalplus/humanevalplus", "dataset/evalplus/humanevalplus"),
    ("evalplus/mbppplus", "dataset/evalplus/mbppplus"),
]
if os.environ.get("REPRO_DOWNLOAD_ALL") == "1":
    repos = [
        ("UCSB-SURFI/SeCodePLT", "dataset/secodeplt"),
        ("s2e-lab/sallm", "dataset/sallm"),
    ] + repos

for repo_id, local_dir in repos:
    print(f"Downloading {repo_id} -> {local_dir}")
    snapshot_download(repo_id=repo_id, repo_type="dataset", local_dir=local_dir)
    print("  OK")
PY
fi

if [[ ! -d "${CWEVAL_ROOT}" ]]; then
  die "CWEval tasks not found at ${CWEVAL_ROOT}. Run with --download or clone dataset/cweval manually."
fi

# ---------------------------------------------------------------------------
# 2. Human reference corpus
# ---------------------------------------------------------------------------
if ! maybe_skip "${REF_CORPUS}"; then
  log "Building CWEval human references → ${REF_CORPUS}"
  "${PYTHON}" -m corpus.build \
    --datasets cweval \
    --cweval-path "${CWEVAL_ROOT}" \
    --out "${REF_CORPUS}" \
    "${LIMIT_ARGV[@]}"
fi

# ---------------------------------------------------------------------------
# 3. AI corpus (LLM, synthetic, or reuse existing)
# ---------------------------------------------------------------------------
MERGE_INPUTS=()

if [[ "${USE_SYNTHETIC}" -eq 1 ]]; then
  if ! maybe_skip "${SYNTHETIC_CORPUS}"; then
    log "Building synthetic insecure CWEval corpus → ${SYNTHETIC_CORPUS}"
    "${PYTHON}" -m corpus.build \
      --datasets cweval-synthetic \
      --cweval-path "${CWEVAL_ROOT}" \
      --out "${SYNTHETIC_CORPUS}" \
      "${LIMIT_ARGV[@]}"
  fi
  MERGE_INPUTS=("${SYNTHETIC_CORPUS}")
elif [[ "${DO_GENERATE}" -eq 1 ]]; then
  if ! maybe_skip "${AI_CORPUS_GPT}"; then
    if [[ -z "${OPENAI_API_KEY:-}" ]]; then
      die "--generate requires OPENAI_API_KEY for ${GPT_MODEL}"
    fi
    log "Generating GPT completions → ${AI_CORPUS_GPT}"
    "${PYTHON}" -m corpus.build \
      --datasets cweval \
      --cweval-path "${CWEVAL_ROOT}" \
      --generate "${GPT_MODEL}" \
      --out "${AI_CORPUS_GPT}" \
      "${LIMIT_ARGV[@]}"
  fi
  if ! maybe_skip "${AI_CORPUS_GEMMA}"; then
    log "Generating Ollama completions → ${AI_CORPUS_GEMMA} (model: ${GEMMA_MODEL})"
    "${PYTHON}" -m corpus.build \
      --datasets cweval \
      --cweval-path "${CWEVAL_ROOT}" \
      --generate "${GEMMA_MODEL}" \
      --out "${AI_CORPUS_GEMMA}" \
      "${LIMIT_ARGV[@]}"
  fi
  MERGE_INPUTS=("${AI_CORPUS_GPT}" "${AI_CORPUS_GEMMA}")
else
  log "Reusing existing AI corpora (--skip-generate)"
  need_file "${AI_CORPUS_GPT}"
  need_file "${AI_CORPUS_GEMMA}"
  MERGE_INPUTS=("${AI_CORPUS_GPT}" "${AI_CORPUS_GEMMA}")
fi

# ---------------------------------------------------------------------------
# 4. Merge multi-model study corpus
# ---------------------------------------------------------------------------
if ! maybe_skip "${MULTI_CORPUS}"; then
  log "Merging corpora → ${MULTI_CORPUS}"
  "${PYTHON}" -m corpus.merge \
    --human-from "${REF_CORPUS}" \
    --inputs "${MERGE_INPUTS[@]}" \
    --out "${MULTI_CORPUS}"
fi

# ---------------------------------------------------------------------------
# 5. Full study (RQ1–RQ5)
# ---------------------------------------------------------------------------
if [[ "${SKIP_STUDY}" -eq 0 ]]; then
  log "Running empirical study → ${RESULTS_DIR}"
  STUDY_ARGS=(
    -m experiments.run_study
    --corpus "${MULTI_CORPUS}"
    --out-dir "${RESULTS_DIR}"
    --runs "${STUDY_RUNS}"
  )
  if [[ "${SKIP_ENERGY}" -eq 1 ]]; then
    STUDY_ARGS+=(--skip-energy)
  fi
  if [[ -n "${LIMIT}" ]]; then
    STUDY_ARGS+=(--limit "${LIMIT}")
  fi
  "${PYTHON}" "${STUDY_ARGS[@]}"
else
  log "Skipping study (--skip-study)"
fi

# ---------------------------------------------------------------------------
# 6. RQ3 energy study (EvalPlus; optional)
# ---------------------------------------------------------------------------
if [[ "${WITH_ENERGY}" -eq 1 ]]; then
  if ! maybe_skip "${EVALPLUS_CORPUS}"; then
    log "Building EvalPlus corpus → ${EVALPLUS_CORPUS}"
    "${PYTHON}" -m corpus.build \
      --datasets evalplus \
      --out "${EVALPLUS_CORPUS}"
  fi
  log "Running RQ3 energy study → ${ENERGY_DIR}"
  ENERGY_ARGS=(
    -m experiments.run_energy
    --corpus "${EVALPLUS_CORPUS}"
    --out-dir "${ENERGY_DIR}"
    --runs "${ENERGY_RUNS}"
    --warmup "${ENERGY_WARMUP}"
    --energy-backend "${ENERGY_BACKEND}"
    --max-samples "${ENERGY_MAX_SAMPLES}"
  )
  if [[ -n "${LIMIT}" ]]; then
    ENERGY_ARGS+=(--limit "${LIMIT}")
  fi
  "${PYTHON}" "${ENERGY_ARGS[@]}"
fi

# ---------------------------------------------------------------------------
# 7. Dedicated baselines run (optional; study already includes RQ5 aggregate)
# ---------------------------------------------------------------------------
if [[ "${WITH_BASELINES}" -eq 1 ]]; then
  log "Running baseline comparison → ${BASELINES_DIR}"
  "${PYTHON}" -m experiments.run_baselines \
    --corpus "${MULTI_CORPUS}" \
    --out-dir "${BASELINES_DIR}"
fi

# ---------------------------------------------------------------------------
# 8. Cross-dataset detection study (SALLM + SecurityEval + EvalPlus; RQ5.7/RQ7)
# ---------------------------------------------------------------------------
if [[ "${WITH_DETECTION}" -eq 1 ]]; then
  DETECTION_DIR="${RESULTS_DIR%/*}/detection_study"
  log "Running cross-dataset detection study → ${DETECTION_DIR}"
  DETECTION_ARGS=(
    -m experiments.run_detection_study
    --out-dir "${DETECTION_DIR}"
  )
  if [[ -n "${LIMIT}" ]]; then
    DETECTION_ARGS+=(--limit "${LIMIT}")
  fi
  "${PYTHON}" "${DETECTION_ARGS[@]}"
fi

# ---------------------------------------------------------------------------
# 9. LLM repair study (RQ4-B; optional — requires OPENAI_API_KEY)
# ---------------------------------------------------------------------------
if [[ "${WITH_LLM_REPAIR}" -eq 1 ]]; then
  if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    die "--with-llm-repair requires OPENAI_API_KEY"
  fi
  REPAIR_DIR="${RESULTS_DIR%/*}/llm_repair"
  log "Running LLM repair study → ${REPAIR_DIR}"
  "${PYTHON}" -m experiments.run_llm_repair \
    --corpus "${MULTI_CORPUS}" \
    --cweval-root "${CWEVAL_ROOT%/benchmark/core/py}" \
    --out-dir "${REPAIR_DIR}"
fi

# ---------------------------------------------------------------------------
# 10. Secure@k / Vulnerable@k (RQ6)
# ---------------------------------------------------------------------------
if [[ "${WITH_SECURE_AT_K}" -eq 1 ]]; then
  SECUREATK_DIR="${RESULTS_DIR%/*}/secure_at_k"
  log "Running secure@k / vulnerable@k → ${SECUREATK_DIR}"
  "${PYTHON}" -m experiments.rq6_secure_at_k \
    --corpus "${MULTI_CORPUS}" \
    --out-dir "${SECUREATK_DIR}"
fi

log "Done."
log "  Merged corpus: ${MULTI_CORPUS}"
if [[ "${SKIP_STUDY}" -eq 0 ]]; then
  log "  Study results: ${RESULTS_DIR}/ (CSVs, summary.json, METHODS.md, plots/)"
fi
if [[ "${WITH_ENERGY}" -eq 1 ]]; then
  log "  Energy results: ${ENERGY_DIR}/"
fi
if [[ "${WITH_BASELINES}" -eq 1 ]]; then
  log "  Baselines: ${BASELINES_DIR}/"
fi
if [[ "${WITH_DETECTION}" -eq 1 ]]; then
  log "  Detection study: ${RESULTS_DIR%/*}/detection_study/"
fi
if [[ "${WITH_LLM_REPAIR}" -eq 1 ]]; then
  log "  LLM repair: ${RESULTS_DIR%/*}/llm_repair/"
fi
if [[ "${WITH_SECURE_AT_K}" -eq 1 ]]; then
  log "  Secure@k: ${RESULTS_DIR%/*}/secure_at_k/"
fi
