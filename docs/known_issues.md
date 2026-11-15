# MLShield: Known Issues Log

Issues found while working through the remediation plan that are **not fixed yet** (or fixed only
partly). Each has an ID, where it was found, what is known, and where it will be handled. Closed
items stay in the table with the commit that closed them.

| ID | Found in | Issue | Status / next step |
|---|---|---|---|
| KI-01 | M0 | **Model signature mismatch (B-03).** The retrained `baseline_model.joblib` (md5 `8b1803...`) does not match the DVC-recorded and signed artifact (md5 `a898ab...`). The original model and the private signing key are not on this machine, so the gate correctly reports integrity failure and FAIL. | Open. Needs owner decision (new trust root or restore original). Handled in M4. |
| KI-02 | M0 | **Root cause of the empty-stdout problem is not fully understood.** Inside the API server `pip-audit`'s stdout came back empty although the scan completed; the same call from a normal shell works. Closing stdin did not fix it; writing to a file with `-o` did. | Mitigated, not explained. Revisit if the same pattern appears with other subprocess tools (e.g. `cyclonedx-py`, Trivy in M1). |
| KI-03 | M0 | **The 7 reported vulnerabilities in 3 packages have not been reviewed.** The gate now counts them (score 30) but no one has decided which are real exposure, which can be upgraded, or which need a documented exception. | Open. Policy and exceptions in M6; a first review should happen sooner. |
| KI-04 | M0 | **Attack lab not rerun on this machine.** The 50-minute lab (6 runs) passed on the original Linux sandbox. It has not been run on this Windows machine since the fixes. | Open. Run before M7 changes the recovery cycle. |
| KI-05 | M0 | **Shell validation scripts (`scripts/validate_phase*.sh`) not run on Windows.** The project was built on Linux. | Open. Run under Git Bash or Docker in M1/M9. |
| KI-06 | M0 | **Robustness score overstates robustness.** The gate uses a quick check (1% drop); the project's own stronger black-box attack drops accuracy 1.00 to 0.65. | Open. M6. |
| KI-07 | M0 | **Poisoning detector evidence is self-generated.** Recall 0.966 and FPR 0.033 were measured on poison the project injected. | Open. M6. |
| KI-08 | M0 | **`POST /auth/dev-token` issues any role to any caller.** | Open. M3 (must be closed before any deployment). |
| KI-09 | M0 | **Mixed line endings.** Git warns that LF will be replaced by CRLF on several files; tracked files were originally written with LF on Linux. | Open, low priority. Add `.gitattributes` to normalize. |
| KI-10 | M0 | **Dependency-scan cache is per process.** Two API workers each run their own scan, and a restart rescans (about 90 s, run at startup). | Acceptable for now. Move to PostgreSQL/Redis in M2. |
| KI-11 | M0 | **Dashboard's first load depends on the warm-up scan.** Until the startup scan finishes, Overview and Model Card wait on it. | Open. Becomes a background job with a job ID in M2. |
| KI-12 | M0 | **`PROJECT_STATUS.md` and `.claude/launch.json` are untracked.** `launch.json` holds paths specific to this machine. | Decide whether to commit `PROJECT_STATUS.md`; keep `launch.json` local. |
| KI-13 | M1 | **Dockerfile base image is Python 3.11; local venv is Python 3.12.** Pinned versions (pandas 3.0.5, numpy 2.4.6, scikit-learn 1.9.1) were tested here on 3.12. | Verify in M1 by building and running the actual image. |
| KI-14 | M0 | **Docker build and run were never verified by anyone** (original sandbox blocked Docker Hub). | Being worked on in M1. |
| KI-15 | M0 | **Mid-semester `.pptx` is untracked** in the repo root. | Not mine; owner to decide whether to commit. |

## Closed

| ID | Issue | Closed by |
|---|---|---|
| KI-C1 | Dependency scan scored 0 on every run (bare `pip-audit` launcher, then empty stdout in the server). | `21367a9` (verified through the API: status ok, score 30, cached call 0.36 s) |
| KI-C2 | `progress.md` listed Phase 10 as not started. | `21367a9` |
