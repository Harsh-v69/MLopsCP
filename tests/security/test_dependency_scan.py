"""Phase 6 gate tests for the dependency scan / SBOM generation. Protocol
locked in docs/phase6_security_gate_v2_spec.md (Part B)."""
from pathlib import Path

import pytest

from src.security.dependency_scan import (
    count_vulnerabilities,
    generate_sbom,
    run_pip_audit,
    validate_sbom_structure,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
VULNERABLE_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "vulnerable_requirements.txt"


def test_seeded_vulnerability_is_caught():
    """urllib3==1.24.1 has real, long-documented CVEs - this is a scan
    TARGET, never installed into this project's own environment."""
    result = run_pip_audit(VULNERABLE_FIXTURE)
    n_vulns = count_vulnerabilities(result)
    assert n_vulns >= 1, f"expected pip-audit to find vulnerabilities in the seeded fixture, found {n_vulns}"


def test_seeded_vulnerability_is_caught_reliably():
    """Same scan, run twice - the vulnerability database doesn't change
    mid-test, so this must not be flaky (Phase 6 plan wording)."""
    result_1 = run_pip_audit(VULNERABLE_FIXTURE)
    result_2 = run_pip_audit(VULNERABLE_FIXTURE)
    assert count_vulnerabilities(result_1) >= 1
    assert count_vulnerabilities(result_2) >= 1


def test_sbom_generation_and_structure(tmp_path):
    sbom_path = tmp_path / "sbom.json"
    sbom = generate_sbom(REPO_ROOT / "requirements.txt", sbom_path)
    problems = validate_sbom_structure(sbom, expected_min_components=1)
    assert problems == [], f"SBOM structural problems: {problems}"


def test_sbom_covers_declared_packages(tmp_path):
    sbom_path = tmp_path / "sbom.json"
    sbom = generate_sbom(REPO_ROOT / "requirements.txt", sbom_path)
    component_names = {c["name"].lower() for c in sbom["components"]}

    declared = set()
    for line in (REPO_ROOT / "requirements.txt").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            declared.add(line.split("==")[0].lower())

    missing = declared - component_names
    assert not missing, f"SBOM is missing declared packages: {missing}"


def test_cached_scan_reuses_success_but_never_caches_failure(tmp_path, monkeypatch):
    from src.security import dependency_scan as ds

    reqs = tmp_path / "requirements.txt"
    reqs.write_text("requests==2.0.0\n")
    ds._audit_cache.clear()
    calls = []

    def fake_audit(path):
        calls.append(path)
        if len(calls) == 1:
            raise RuntimeError("scan failed")
        return {"dependencies": []}

    monkeypatch.setattr(ds, "run_pip_audit", fake_audit)

    with pytest.raises(RuntimeError):
        ds.run_pip_audit_cached(reqs)  # failure must not be cached
    assert ds.run_pip_audit_cached(reqs) == ({"dependencies": []}, 0)  # fresh run
    assert ds.run_pip_audit_cached(reqs)[0] == {"dependencies": []}  # served from cache
    assert len(calls) == 2

    reqs.write_text("requests==2.0.0\nflask==1.0\n")  # file changed -> rescan
    ds.run_pip_audit_cached(reqs)
    assert len(calls) == 3
    ds._audit_cache.clear()
