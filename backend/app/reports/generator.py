"""Report generator.

Orchestrates one full assessment (discovery -> graph -> detectors -> session
analysis), maps every verified result into a scored Finding, and renders a
prioritized, redacted report as Markdown + JSON, plus a combined re-test file.
"""
import datetime
import json
import os
from dataclasses import asdict

from app.config import LAB, AssessmentConfig
from app.engine import verification as V
from app.engine.auth_analyzer import analyze
from app.engine.authorization import run as run_authz
from app.engine.bola import run_bola
from app.engine.rbac import run_rbac
from app.models.finding import Finding

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None"]


def _has_secret_fields(vf) -> bool:
    for e in vf.evidence:
        body = (e.get("response") or {}).get("body") or (e.get("response") or {}).get("sample")
        if isinstance(body, dict) and any(k in body for k in V.SENSITIVE_KEYS):
            return True
    return False


def run_assessment(config: AssessmentConfig = LAB):
    """Run the full pipeline once; return (authorization graph, sorted findings)."""
    shared = run_authz(config)                       # one discovery+graph, reused
    graph = shared[0]
    verified = run_bola(config, shared=shared) + run_rbac(config, shared=shared)
    findings = [Finding.from_verified(vf) for vf in verified]

    # weak-session finding (forgeable identity) from the auth analyzer
    forgeable = next((o for o in analyze(config).observations
                      if o.id == "SESS-FORGEABLE-IDENTITY"), None)
    if forgeable:
        findings.append(Finding.from_session(forgeable))

    # excessive-exposure finding, derived if any response leaked secret fields
    exposing = [vf for vf in verified if _has_secret_fields(vf)]
    if exposing:
        findings.append(Finding.exposure(exposing[0].evidence))

    findings.sort(key=lambda f: (-f.cvss_score, f.category, f.id))
    return graph, findings


def collect_findings(config: AssessmentConfig = LAB) -> list[Finding]:
    return run_assessment(config)[1]


def severity_summary(findings) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def render_markdown(findings, config: AssessmentConfig) -> str:
    counts = severity_summary(findings)
    out = [
        "# AuthGraph Sentinel - Assessment Report",
        "",
        f"**Target:** {config.name} ({config.base_url})  ",
        f"**Generated:** {datetime.datetime.utcnow().isoformat()}Z  ",
        f"**Total findings:** {len(findings)}",
        "",
        "## Severity summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    out += [f"| {s} | {counts[s]} |" for s in ["Critical", "High", "Medium", "Low"]]
    out += ["", "## Findings (highest CVSS first)"]

    for n, f in enumerate(findings, 1):
        out += [
            "",
            f"### {n}. {f.title}",
            "",
            f"- **ID:** {f.id}",
            f"- **Category:** {f.category}",
            f"- **Severity:** {f.severity} (CVSS {f.cvss_score})",
            f"- **Vector:** `{f.cvss_vector}`",
            f"- **Confidence:** {f.confidence}",
        ]
        if f.endpoint:
            out.append(f"- **Endpoint:** `{f.endpoint}`")
        if f.actor_role:
            out.append(f"- **Actor role:** {f.actor_role}")
        out.append(f"- **Re-test scenario:** {'available' if f.retest else 'n/a'}")
        out += [
            "",
            f"**Business impact.** {f.business_impact}",
            "",
            f"**Remediation.** {f.remediation}",
            "",
            "**Evidence (redacted).**",
            "",
            "```json",
            json.dumps(f.evidence, indent=2),
            "```",
        ]
    return "\n".join(out)


def generate(config: AssessmentConfig = LAB, out_dir: str = "."):
    findings = collect_findings(config)
    os.makedirs(out_dir, exist_ok=True)
    md_path = os.path.join(out_dir, "report.md")
    json_path = os.path.join(out_dir, "report.json")
    retest_path = os.path.join(out_dir, "retest_scenarios.json")

    with open(md_path, "w") as fh:
        fh.write(render_markdown(findings, config))
    with open(json_path, "w") as fh:
        json.dump([asdict(f) for f in findings], fh, indent=2)
    with open(retest_path, "w") as fh:
        json.dump({"generated": datetime.datetime.utcnow().isoformat() + "Z",
                   "scenarios": [f.retest for f in findings if f.retest]}, fh, indent=2)
    return findings, md_path


if __name__ == "__main__":
    findings, path = generate()
    counts = severity_summary(findings)
    print("Assessment complete.\n")
    print("Severity   Count")
    print("-" * 18)
    for s in ["Critical", "High", "Medium", "Low"]:
        print(f"{s:10} {counts[s]}")
    print(f"\n{len(findings)} findings (highest CVSS first):\n")
    for f in findings:
        print(f"  {f.cvss_score:>4}  {f.severity:8} {f.category:18} {f.id}")
    print(f"\nWritten: report.md, report.json, retest_scenarios.json -> {os.path.dirname(path) or '.'}")
