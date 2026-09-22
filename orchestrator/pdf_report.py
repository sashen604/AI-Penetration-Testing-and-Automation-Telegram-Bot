"""PDF report generation (summary + detailed) with severity color-coding.

Severity color scheme (as specified): info=light green, low=light blue,
medium=yellow, high=red, critical=dark blue. Colors live in
pdf_templates/_style.html, not here -- keep this file about data assembly.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

from orchestrator import db
from orchestrator.storage import target_dir

TEMPLATE_DIR = Path(__file__).resolve().parent / "pdf_templates"
_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _severity_counts(findings: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = (f["severity"] or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _context_for(job_id: int) -> dict | None:
    job = db.get_job(job_id)
    if not job:
        return None
    findings = [dict(f) for f in db.list_findings(job_id=job_id, limit=1000)]
    # highest severity first, reads better in a report than insertion order
    sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: sev_rank.get((f["severity"] or "info").lower(), 99))

    screenshot_paths = {
        f["id"]: f["screenshot_path"] for f in findings if f.get("screenshot_path")
    }
    manual_steps = {}
    for f in findings:
        raw = f.get("manual_steps") or "[]"
        try:
            manual_steps[f["id"]] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            manual_steps[f["id"]] = [raw] if raw else []

    return {
        "job": dict(job),
        "findings": findings,
        "severity_counts": _severity_counts(findings),
        "severity_order": SEVERITY_ORDER,
        "screenshot_paths": screenshot_paths,
        "manual_steps": manual_steps,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def generate_summary_pdf(job_id: int) -> str | None:
    ctx = _context_for(job_id)
    if ctx is None:
        return None
    html = _env.get_template("summary.html").render(**ctx)
    out_path = target_dir(ctx["job"]["target"]) / f"report_job{job_id}_summary.pdf"
    HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf(str(out_path))
    return str(out_path)


def generate_detailed_pdf(job_id: int) -> str | None:
    ctx = _context_for(job_id)
    if ctx is None:
        return None
    html = _env.get_template("detailed.html").render(**ctx)
    out_path = target_dir(ctx["job"]["target"]) / f"report_job{job_id}_detailed.pdf"
    HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf(str(out_path))
    return str(out_path)
