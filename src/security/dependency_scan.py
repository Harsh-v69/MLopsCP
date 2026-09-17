"""Phase 6 — Part B: dependency vulnerability scan + SBOM generation.

Tooling and protocol locked in docs/phase6_security_gate_v2_spec.md before
this file was written: pip-audit against OSV.dev, CycloneDX SBOM via
cyclonedx-py. Both are invoked as subprocesses (their stable, documented
CLI) rather than internal APIs, since neither project guarantees a stable
importable API.
"""
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def run_pip_audit(requirements_path: Path) -> dict:
    """Runs pip-audit against a requirements file, returns parsed JSON
    findings. Does not raise on found vulnerabilities (pip-audit exits
    non-zero when it finds any) - that's the expected, useful case."""
    result = subprocess.run(
        ["pip-audit", "-r", str(requirements_path), "--format", "json"],
        capture_output=True,
        text=True,
    )
    try:
        findings = json.loads(result.stdout)
    except json.JSONDecodeError:
        findings = {"error": "could not parse pip-audit output", "stdout": result.stdout, "stderr": result.stderr}
    return findings


def count_vulnerabilities(pip_audit_result: dict) -> int:
    dependencies = pip_audit_result.get("dependencies", [])
    return sum(len(dep.get("vulns", [])) for dep in dependencies)


def generate_sbom(requirements_path: Path, output_path: Path) -> dict:
    """Generates a CycloneDX JSON SBOM via cyclonedx-py's own --validate
    flag (schema validation built into the tool, not reimplemented here)."""
    result = subprocess.run(
        [
            "cyclonedx-py", "requirements", str(requirements_path),
            "--of", "json", "-o", str(output_path), "--validate",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cyclonedx-py failed: {result.stderr}")

    return json.loads(output_path.read_text())


def validate_sbom_structure(sbom: dict, expected_min_components: int = 1) -> list:
    """Independent structural check on top of cyclonedx-py's own
    --validate, so the gate doesn't rely solely on the generating tool's
    self-assessment. Returns a list of problems; empty means valid."""
    problems = []
    if sbom.get("bomFormat") != "CycloneDX":
        problems.append(f"bomFormat is '{sbom.get('bomFormat')}', expected 'CycloneDX'")
    if "specVersion" not in sbom:
        problems.append("missing specVersion")
    components = sbom.get("components", [])
    if len(components) < expected_min_components:
        problems.append(f"only {len(components)} components, expected >= {expected_min_components}")
    for c in components:
        if "name" not in c or "version" not in c:
            problems.append(f"component missing name/version: {c}")
    return problems


def main() -> int:
    requirements_path = REPO_ROOT / "requirements.txt"
    sbom_path = REPO_ROOT / "data" / "processed" / "sbom.json"
    sbom_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Scanning {requirements_path} with pip-audit...")
    audit_result = run_pip_audit(requirements_path)
    n_vulns = count_vulnerabilities(audit_result)
    print(f"  {n_vulns} known vulnerabilities found in this project's own dependencies")
    print("  (this is a project health record, not the Phase 6 gate criterion - "
          "see docs/phase6_security_gate_v2_spec.md Part B)")

    print(f"Generating SBOM to {sbom_path}...")
    sbom = generate_sbom(requirements_path, sbom_path)
    problems = validate_sbom_structure(sbom)
    if problems:
        print("SBOM validation FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"  SBOM valid: {len(sbom['components'])} components, CycloneDX {sbom['specVersion']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
