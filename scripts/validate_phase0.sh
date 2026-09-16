#!/usr/bin/env bash
# Phase 0 validation gate.
#
# Per the project plan: "A fresh clone of the repo, on a clean machine, can
# load the dataset and reproduce an identical train/test split hash. The
# security-score formula document exists and is reviewed before Phase 5."
#
# This script checks every part of that gate it is possible to check from
# the repo itself. It does NOT build/run the Docker image (see
# docs/phase0_environment_note.md for why, and how to verify that part
# separately) — everything else is fully automated and must all pass.
set -euo pipefail
cd "$(dirname "$0")/.."

FAIL=0

echo "=== Phase 0 Validation Gate ==="
echo

# 1. Raw dataset integrity — files present and match the locked hashes.
echo "[1/4] Raw dataset integrity"
EXPECTED_TRAIN="1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95"
EXPECTED_TEST="fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84"

ACTUAL_TRAIN=$(sha256sum data/raw/KDDTrain+.txt | awk '{print $1}')
ACTUAL_TEST=$(sha256sum data/raw/KDDTest+.txt | awk '{print $1}')

if [ "$ACTUAL_TRAIN" = "$EXPECTED_TRAIN" ]; then
  echo "  KDDTrain+.txt hash OK"
else
  echo "  FAIL: KDDTrain+.txt hash mismatch (expected $EXPECTED_TRAIN, got $ACTUAL_TRAIN)"
  FAIL=1
fi

if [ "$ACTUAL_TEST" = "$EXPECTED_TEST" ]; then
  echo "  KDDTest+.txt hash OK"
else
  echo "  FAIL: KDDTest+.txt hash mismatch (expected $EXPECTED_TEST, got $ACTUAL_TEST)"
  FAIL=1
fi
echo

# 2. Security score formula document exists and defines thresholds.
echo "[2/4] Security-score formula document"
if [ -f docs/security_gate_formula.md ] && grep -q "PASS" docs/security_gate_formula.md \
   && grep -q "BORDERLINE" docs/security_gate_formula.md && grep -q "FAIL" docs/security_gate_formula.md; then
  echo "  docs/security_gate_formula.md exists and defines PASS/BORDERLINE/FAIL"
else
  echo "  FAIL: docs/security_gate_formula.md missing or incomplete"
  FAIL=1
fi
echo

# 3. Deterministic split reproducibility — run twice, hashes must match each
#    other AND the locked expected hash committed in Phase 0.
echo "[3/4] Deterministic split reproducibility"
EXPECTED_SPLIT_HASH=$(cat data/processed/expected_split_hash.txt)

RUN1=$(python3 -m src.data.load_dataset | tail -1 | awk -F': ' '{print $2}')
RUN2=$(python3 -m src.data.load_dataset | tail -1 | awk -F': ' '{print $2}')

if [ "$RUN1" = "$RUN2" ]; then
  echo "  Two runs produced identical split hash: $RUN1"
else
  echo "  FAIL: split hash differs between runs ($RUN1 vs $RUN2) — split is not deterministic"
  FAIL=1
fi

if [ "$RUN1" = "$EXPECTED_SPLIT_HASH" ]; then
  echo "  Split hash matches locked expected value from Phase 0"
else
  echo "  FAIL: split hash does not match locked value (expected $EXPECTED_SPLIT_HASH, got $RUN1)"
  FAIL=1
fi
echo

# 4. Environment sanity — required project files exist.
echo "[4/4] Environment scaffolding"
for f in docker/Dockerfile docker-compose.yml requirements.txt progress.md; do
  if [ -f "$f" ]; then
    echo "  $f present"
  else
    echo "  FAIL: $f missing"
    FAIL=1
  fi
done
echo

if [ "$FAIL" -eq 0 ]; then
  echo "=== PHASE 0 GATE: PASSED ==="
  exit 0
else
  echo "=== PHASE 0 GATE: FAILED ==="
  exit 1
fi
