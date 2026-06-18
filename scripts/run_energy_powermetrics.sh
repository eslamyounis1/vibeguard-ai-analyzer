#!/usr/bin/env bash
# Run the RQ3 energy study with Apple M-series CPU power counter (powermetrics).
#
# Usage:
#   sudo bash scripts/run_energy_powermetrics.sh
#
# Why sudo: powermetrics reads CPU-package power counters, which require root
# on macOS. Without root the backend falls back to wall-time-only measurements
# (energy_joules = null). Run as root to get direct joule estimates.
#
# Outputs → results/energy_powermetrics/
#   rq3_energy.csv       Per-sample wall-time + energy stats (mean ± CI)
#   rq3_correlation.csv  Perf-smell vs no-smell group comparison
#   summary.json         Backend, counts, correlation table
#   METHODS.md           Protocol, environment, threats
#
# Corpus: data/corpus/synthetic_perf.jsonl (40 synthetic algorithmic tasks)
# Backend: powermetrics (Apple M-series CPU power, 100 ms sampling)
# Runs:    10 per sample (2 warm-up discarded)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

# Verify we have root
if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: This script must be run as root (sudo) to enable powermetrics." >&2
  echo "Usage: sudo bash scripts/run_energy_powermetrics.sh" >&2
  exit 1
fi

# Verify corpus exists
CORPUS="data/corpus/synthetic_perf.jsonl"
if [[ ! -f "${CORPUS}" ]]; then
  echo "ERROR: Corpus not found: ${CORPUS}" >&2
  echo "Run: python - < scripts/_build_perf_corpus.py  (or re-run the corpus build step)" >&2
  exit 1
fi

OUT_DIR="results/energy_powermetrics"
mkdir -p "${OUT_DIR}"

echo "=== RQ3 Energy Study (powermetrics backend) ==="
echo "Corpus: ${CORPUS}"
echo "Output: ${OUT_DIR}"
echo "Runs/sample: 10 (+ 2 warm-up)"
echo

VIBEGUARD_POWERMETRICS=1 python -m experiments.run_energy \
  --corpus "${CORPUS}" \
  --out-dir "${OUT_DIR}" \
  --energy-backend powermetrics \
  --runs 10 \
  --warmup 2 \
  --no-tests

echo
echo "=== Results summary ==="
python -c "
import json, sys
s = json.load(open('${OUT_DIR}/summary.json'))
print(f'Backend:  {s[\"energy_backend_used\"]}')
print(f'Measured: {s[\"n_measured\"]}/{s[\"n_corpus\"]} samples')
for c in s['correlation']:
    m = c['metric']
    mw = c.get('mean_with_perf')
    mc = c.get('mean_without_perf')
    if mw and mc:
        print(f'{m}: smelly={mw:.4f}, clean={mc:.4f}, ratio={mw/mc:.1f}x, delta={c[\"cliffs_delta\"]}, p={c[\"p_value\"]:.2e}')
    else:
        print(f'{m}: n_smelly={c[\"n_with_perf_finding\"]}, n_clean={c[\"n_without_perf_finding\"]}')
"
echo
echo "Full results: ${OUT_DIR}/"
