"""Markdown report generation per job."""
import json
from pathlib import Path

from orchestrator import db
from orchestrator.storage import target_dir


def generate_report(job_id: int) -> str:
    job = db.get_job(job_id)
    if not job:
        return ""
    findings = db.list_findings(job_id=job_id)

    risk_analysis = job["risk_analysis"] if "risk_analysis" in job.keys() else ""
    lines = [
        f"# Bug Bounty Scan Report — {job['target']}",
        f"Job #{job['id']} | Status: {job['status']} | Created: {job['created_at']}",
        f"\n{job['summary']}\n",
    ]
    if risk_analysis:
        lines += ["## Executive Summary", f"\n{risk_analysis}\n"]

    recon_suggestions = job["recon_suggestions"] if "recon_suggestions" in job.keys() else ""
    if recon_suggestions:
        lines += [
            "## Manual Testing Suggestions",
            "_Generated from the recon surface, informed by a reference technique corpus -- most useful when automated scanners found little or nothing._",
            f"\n{recon_suggestions}\n",
        ]

    lines.append("## Findings")
    if not findings:
        lines.append("\nNo findings recorded.")
    for f in findings:
        lines += [
            f"\n### [{f['severity'].upper()}] {f['title']} (ID #{f['id']})",
            f"- Tool: {f['tool']} ({f['kind']})",
            f"- URL: {f['matched_url']}",
            f"- Verdict: {f['verdict']} (AI confidence: {f['ai_confidence']:.2f})",
        ]
        description = f["description"] if "description" in f.keys() else ""
        if description:
            lines.append(f"- Description: {description}")
        risk = f["risk"] if "risk" in f.keys() else ""
        if risk:
            lines.append(f"- Risk: {risk}")
        reasoning = f["reasoning"] if "reasoning" in f.keys() else ""
        if reasoning:
            lines.append(f"- AI reasoning: {reasoning}")

        steps_raw = f["manual_steps"] if "manual_steps" in f.keys() else ""
        try:
            steps = json.loads(steps_raw) if steps_raw else []
        except json.JSONDecodeError:
            steps = [steps_raw]
        if steps:
            lines.append("- Manual Testing Procedure:")
            lines.extend(f"  {i}. {s}" for i, s in enumerate(steps, 1))

        shot = f["screenshot_path"] if "screenshot_path" in f.keys() else ""
        if shot:
            # report.md and screenshots/ both live directly under the target dir
            lines.append(f"- PoC screenshot:\n\n  ![PoC](screenshots/{Path(shot).name})")

        remediation = f["remediation"] if "remediation" in f.keys() else ""
        if remediation and remediation != "N/A":
            lines.append(f"- Remediation: {remediation}")

    report_text = "\n".join(lines)
    out_path = target_dir(job["target"]) / f"report_job{job_id}.md"
    out_path.write_text(report_text)
    return str(out_path)
