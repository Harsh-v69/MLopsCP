#!/usr/bin/env bash
# Phase 8 validation gate — see docs/phase8_governance_spec.md.
#   1. RBAC: all 44 role x action combinations correct, plus
#      expired/forged/malformed-token denial.
#   2. Audit log: in-place tamper detected; the anchor-specific rollback
#      attack (tamper + full recompute) caught by verify_against_anchors()
#      specifically, not just the plain chain check.
#   3. Approval workflow: BORDERLINE produces a complete, attributable
#      record; unauthorized attempts denied and still logged; PASS/FAIL
#      have no approval step.
set -uo pipefail
cd "$(dirname "$0")/.."
FAIL=0

echo "=== Phase 8 Validation Gate ==="
echo

source .venv/bin/activate

echo "[1/2] Full governance test suite (RBAC matrix + audit log + approval workflow)"
MLFLOW_DISABLE_AGENT_HINT=1 python3 -m pytest tests/governance/ -v > /tmp/phase8_pytest.log 2>&1
PYTEST_EXIT=$?
tail -15 /tmp/phase8_pytest.log
if [ "$PYTEST_EXIT" -eq 0 ]; then
  echo "  Full governance suite passed (67 tests: 44 RBAC matrix + fail-closed cases + tamper/anchor + approval workflow)"
else
  echo "  FAIL: governance test suite failed"
  FAIL=1
fi
echo

echo "[2/2] Live demonstration against a real, persisted audit log"
python3 -c "
from src.governance.audit_log import AuditLog
from src.governance.auth import issue_token, APPROVER, DATA_ENGINEER
from src.governance.approval import approve_or_reject, log_gate_result
from src.security.gate import GateResult, run_gate

log = AuditLog()  # real, committed log path (data/audit/audit_log.jsonl)

# Log the real, current live gate result (Phase 7).
real_result = run_gate()
log_gate_result(real_result, log)
print(f'Logged real live gate result: {real_result.decision} (score={real_result.security_score:.2f})')

# Demonstrate the BORDERLINE approval path with a synthetic result, since
# this project's real model currently PASSes outright.
borderline = GateResult(data_score=65, model_score=60, dependency_score=70,
                         security_score=63.75, integrity_component=100, decision='BORDERLINE')
log_gate_result(borderline, log)

denied = approve_or_reject(borderline, issue_token('demo-data-engineer', DATA_ENGINEER),
                            'approved', 'attempting without authority', log)
print(f'Unauthorized approval attempt: recorded={denied.recorded} ({denied.reason})')

approved = approve_or_reject(borderline, issue_token('demo-approver', APPROVER),
                              'approved', 'Phase 8 gate demonstration - reviewed synthetic borderline case', log)
print(f'Authorized approval: recorded={approved.recorded}, actor={approved.audit_entry[\"actor\"]}')

anchor = log.anchor_head()
print(f'Anchored head hash at seq={anchor[\"seq_at_anchor\"]} to {log.anchor_path}')

chain = log.verify_chain()
anchors = log.verify_against_anchors()
print(f'verify_chain: valid={chain.valid}, n_entries={chain.n_entries}')
print(f'verify_against_anchors: valid={anchors.valid}, n_anchors_checked={anchors.n_anchors_checked}')

import sys
sys.exit(0 if (chain.valid and anchors.valid and approved.recorded and not denied.recorded) else 1)
"
LIVE_EXIT=$?
if [ "$LIVE_EXIT" -eq 0 ]; then
  echo "  Live demonstration completed and verified clean"
else
  echo "  FAIL: live demonstration did not complete cleanly"
  FAIL=1
fi
echo

if [ "$FAIL" -eq 0 ]; then
  echo "=== PHASE 8 GATE: PASSED ==="
  exit 0
else
  echo "=== PHASE 8 GATE: FAILED ==="
  exit 1
fi
