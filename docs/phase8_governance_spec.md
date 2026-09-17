# Phase 8 — Governance Layer Spec (RBAC + Tamper-Evident Audit Log)

Locked before `src/governance/` is written, same practice as every prior
phase. This is the phase that makes the project's SDG 16 claim
("accountable, transparent institutions", not just resilient
infrastructure) into something checkable rather than asserted — see
`progress.md`'s "What this project is" section.

## Part A — RBAC

### Roles (locked to the project plan's own list)

The project plan names two slightly different role lists in different
sections (tech stack §9: "Data Engineer, ML Engineer, Security Reviewer,
Approver"; suggested roles §13: "ML Engineer, Security Reviewer, Approver,
Platform/DevOps"). This phase uses **§9's list**, since that's the one
`progress.md`'s own Phase 7 "Next" note already committed to before this
spec was written:

| Role | What it can do (permissions) |
|---|---|
| **Data Engineer** | `trigger_ingest`, `trigger_validate`, `view_data_scan_result` |
| **ML Engineer** | `trigger_train`, `trigger_evaluate`, `view_model_metrics` |
| **Security Reviewer** | `view_security_gate_result`, `view_data_scan_result`, `view_model_metrics`, `view_audit_log` |
| **Approver** | `view_borderline_queue`, `approve_deployment`, `reject_deployment`, `view_security_gate_result`, `view_audit_log` |

Design rule: **least privilege, no implicit role hierarchy.** There is no
"admin" role that can do everything — each role's permission set is
exactly what §13's own role description says that role does. A Data
Engineer cannot approve a deployment; an Approver cannot trigger training.
Audit-log read access is scoped to the two compliance-relevant roles
(Security Reviewer, Approver), not granted to every role by default — this
is a deliberate least-privilege choice, not an oversight, and is exactly
the kind of assumption the test matrix below (Part D) is built to catch if
wrong.

### Token scheme

- **JWT, HMAC-signed (HS256)**, carrying `sub` (a human-readable actor
  identifier, e.g. `"alice"` — this is what makes an audit log entry
  attributable to a *named* person, not just a role), `role`, `iat`, and
  `exp` (default 1 hour).
- The signing secret is generated once and kept **outside the repo**
  (`~/mlshield-governance/jwt_secret.key`) — same documented MVP stand-in
  pattern as Phase 5's private signing key. A real deployment would issue
  tokens from an external identity provider (OAuth/OIDC — Okta, Keycloak,
  Auth0) and verify against that provider's public keys, not a shared
  local HMAC secret; this stands in for that boundary in an environment
  with no such infrastructure.
- `authorize(token, action) -> AuthResult` decodes and verifies the token
  (signature + expiry), looks up the role's permission set, and returns
  whether `action` is allowed — plus the `subject` and `role`, so callers
  never have to re-parse the token to attribute an action.
- An invalid, expired, or unsigned token is **always denied**, regardless
  of what `action` was requested — fail-closed, matching every other
  security check in this project (Phase 5 integrity, Phase 7 sub-scores).

## Part B — Tamper-evident audit log

### Format

Append-only JSON Lines (`data/audit/audit_log.jsonl`). Each entry:

```json
{
  "seq": 3,
  "timestamp": "2026-...Z",
  "actor": "alice",
  "role": "APPROVER",
  "action": "approve_deployment",
  "details": {...},
  "prev_hash": "<sha256 of entry seq=2>",
  "entry_hash": "<sha256 of this entry's canonical content + prev_hash>"
}
```

- `entry_hash = sha256(canonical_json({seq, timestamp, actor, role, action, details, prev_hash}))`.
- The first entry's `prev_hash` is a fixed genesis constant
  (`"0" * 64`), not null/empty — so an attacker can't claim a forged
  entry is "the first one" by leaving `prev_hash` blank.
- **Append-only at the code level**: `AuditLog.append()` is the only
  write path, always computes `prev_hash` from the current last entry,
  and the log file is never opened in a mode that allows overwriting
  earlier bytes.

### Chain verification

`verify_chain()` walks every entry in order and confirms, for each:
1. `entry["prev_hash"]` equals the *previous* entry's `entry_hash` (or the
   genesis constant, for entry 0).
2. Recomputing `entry_hash` from the entry's own content matches the
   stored `entry_hash`.

Any mismatch — a historical entry's `action`/`details`/`actor` edited in
place, an entry deleted, an entry reordered — breaks at least one of
these two checks and is reported with the exact `seq` where the break
was first detected.

### External anchoring (why the chain alone isn't enough)

A hash chain alone only protects against *inconsistent* tampering. An
attacker with write access to the whole log file can tamper with an old
entry **and** recompute every hash after it, producing an internally
self-consistent chain that still `verify_chain()`s clean. This is exactly
why `docs/security_gate_formula.md`-style projects (and the plan's own
Phase 8 Build item) call for **periodic external anchoring**: writing the
log's current head hash to a location the log's own owner can't quietly
rewrite.

- `anchor_head()` appends `{seq_at_anchor, head_hash, anchor_timestamp}`
  to `~/mlshield-audit-anchors/anchors.jsonl` — **outside the repo**,
  same documented-boundary pattern as the JWT secret and Phase 5's
  signing key. A real deployment would anchor to something genuinely
  independent (a separate write-once cloud log, a public timestamping
  service, or — literally — a blockchain); this stands in for that
  boundary here.
- `verify_against_anchors()` replays the log up to each anchor's
  `seq_at_anchor` and confirms the *replayed* head hash at that point
  still equals the anchor's recorded `head_hash`. This is what catches
  the "tamper old entry, recompute everything after it" attack the plain
  chain check can't: the anchor recorded what the head hash *was* at an
  earlier point in time, independent of whatever the log claims now.

## Part C — BORDERLINE approval workflow

Ties Phase 7's `run_gate()` to RBAC and the audit log:

- **PASS** or **FAIL** → auto-logged to the audit log immediately
  (`action = "security_gate_evaluated"`), no human approval needed or
  possible — matches `docs/security_gate_formula.md`'s decision table.
- **BORDERLINE** → logged as `security_gate_evaluated`, *and* creates a
  pending approval request. Deployment does not proceed until
  `approve_or_reject()` is called with:
  - a valid token whose role is `APPROVER` (anything else → denied,
    fail-closed, and logged as a denied attempt — see Part D),
  - a `decision` (`"approved"` or `"rejected"`),
  - a non-empty `justification` string (an approval with no stated reason
    is not a real approval — matches the SDG 16 "accountable decision"
    framing this whole phase exists for).
  - The resulting audit entry records `actor` (the approver's `sub`),
    `role`, `timestamp`, `decision`, and `justification` together — never
    just the decision alone.

## Part D — Test plan (locked before test code)

### RBAC test matrix

All 4 roles × all 11 distinct permission-gated actions
(`trigger_ingest`, `trigger_validate`, `trigger_train`, `trigger_evaluate`,
`view_data_scan_result`, `view_model_metrics`, `view_security_gate_result`,
`view_audit_log`, `view_borderline_queue`, `approve_deployment`,
`reject_deployment`) = **44 combinations**. For each: assert `authorize()`
returns allowed if and only if that action is in that role's permission
set above. **100% of the 44 combinations must match exactly** — this is
what "100% of unauthorized-action attempts blocked in a test matrix"
(project plan, Phase 8 Validate) means concretely, not just "we tried a
few."

Additional RBAC cases: an expired token denied regardless of role; a
token signed with the wrong secret (forged) denied regardless of claimed
role.

### Audit log tamper detection

1. Build a real log of ≥5 entries, `verify_chain()` passes.
2. Directly edit one historical entry's `action` field in the JSONL file
   (simulating write access to the log itself) → `verify_chain()` detects
   the break at the correct `seq`.
3. **The anchor-specific case**: anchor the log's head, add more entries,
   then tamper with an entry *before* the anchor point and recompute
   every hash after it so `verify_chain()` alone passes clean →
   `verify_against_anchors()` must still catch it (this is the actual
   proof external anchoring does something the chain alone can't).

### Approval workflow

- A BORDERLINE result with a valid Approver token + justification →
  produces a complete audit entry with actor/timestamp/justification all
  present.
- The same, attempted with an ML Engineer token → denied, logged as a
  denied attempt, no approval recorded.
- A PASS or FAIL result → auto-logged, `approve_or_reject()` is never
  reachable/relevant for it.

## Phase 8 gate

1. All 44 RBAC matrix combinations correct, plus expired/forged-token
   denial.
2. Tamper detection: in-place edit caught by `verify_chain()`; pre-anchor
   tamper-and-recompute caught by `verify_against_anchors()` specifically.
3. Every BORDERLINE case in testing produces a complete, attributable
   approval record (actor + role + timestamp + decision + justification).
