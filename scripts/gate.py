# scripts/gate.py
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

import yaml


def load_json(path: str) -> Any:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def count_bandit(bandit: Dict[str, Any], severities: set[str]) -> int:
    """
    Bandit JSON: { "results": [ { "issue_severity": "HIGH"|"MEDIUM"|"LOW", ... } ] }
    """
    results = bandit.get("results", []) if isinstance(bandit, dict) else []
    count = 0
    for r in results:
        sev = (r.get("issue_severity") or "").upper()
        if sev in severities:
            count += 1
    return count


def count_pip_audit(pipa: Dict[str, Any], severities: set[str]) -> int:
    """
    pip-audit JSON typically:
      { "dependencies": [ { "name":..., "version":..., "vulns": [ { "id":..., "severity": "HIGH" } ] } ] }
    Severity is sometimes missing; missing == not counted as blocking here.
    """
    deps = pipa.get("dependencies", []) if isinstance(pipa, dict) else []
    count = 0
    for d in deps:
        for v in d.get("vulns", []) or []:
            sev = (v.get("severity") or "").upper()
            if sev and sev in severities:
                count += 1
    return count


def count_gitleaks(gitleaks: Any) -> int:
    """
    gitleaks JSON is usually a list of findings.
    """
    if isinstance(gitleaks, list):
        return len(gitleaks)
    if isinstance(gitleaks, dict) and isinstance(gitleaks.get("findings"), list):
        return len(gitleaks["findings"])
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", required=True)
    ap.add_argument("--bandit", default="bandit.json")
    ap.add_argument("--pip-audit", dest="pipa", default="pip-audit.json")
    ap.add_argument("--gitleaks", default="gitleaks.json")
    ap.add_argument("--out", default="gate-report.md")
    args = ap.parse_args()

    policy = yaml.safe_load(Path(args.policy).read_text(encoding="utf-8"))

    bandit = load_json(args.bandit)
    pipa = load_json(args.pipa)
    gitleaks = load_json(args.gitleaks)

    bandit_sevs = set(s.upper() for s in policy["fail_on"]["bandit"]["severities"])
    pipa_sevs = set(s.upper() for s in policy["fail_on"]["pip_audit"]["severities"])

    max_bandit = int(policy["fail_on"]["bandit"]["max_allowed"])
    max_pipa = int(policy["fail_on"]["pip_audit"]["max_allowed"])
    max_gitleaks = int(policy["fail_on"]["gitleaks"]["max_allowed"])

    bandit_count = count_bandit(bandit, bandit_sevs)
    pipa_count = count_pip_audit(pipa, pipa_sevs)
    gitleaks_count = count_gitleaks(gitleaks)

    failed = (bandit_count > max_bandit) or (pipa_count > max_pipa) or (gitleaks_count > max_gitleaks)

    lines: List[str] = []
    lines.append("# 🔐 AI-Assisted CI/CD Security Gate Report\n")
    lines.append("## Policy\n")
    lines.append(f"- Bandit severities: `{sorted(bandit_sevs)}` max allowed: **{max_bandit}**")
    lines.append(f"- pip-audit severities: `{sorted(pipa_sevs)}` max allowed: **{max_pipa}**")
    lines.append(f"- gitleaks max allowed: **{max_gitleaks}**\n")

    lines.append("## Results (counts)\n")
    lines.append(f"- Bandit blocking findings: **{bandit_count}**")
    lines.append(f"- pip-audit blocking findings: **{pipa_count}**")
    lines.append(f"- gitleaks findings: **{gitleaks_count}**\n")

    lines.append("## Gate Decision\n")
    lines.append("✅ **PASS**" if not failed else "❌ **FAIL**")
    lines.append("\n---\n")
    lines.append("### Next steps\n")
    if failed:
        lines.append("- Fix the flagged issues, push updates, and the gate will re-run.")
        lines.append("- (Optional) Add AI summary to provide human-readable remediation guidance.")
    else:
        lines.append("- No blocking security findings under current policy thresholds.")

    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")

    return 1 if failed else 0



if __name__ == "__main__":
    sys.exit(main())
