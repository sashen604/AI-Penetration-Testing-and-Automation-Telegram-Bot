"""FastAPI dashboard: submit target+scope, watch jobs, review findings,
and record true/false-positive verdicts that feed the knowledge base."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from orchestrator import db
from orchestrator.ai.chat import ask_about_job
from orchestrator.ai.status import check_ollama_status
from orchestrator.ai.triage import record_lesson_from_verdict
from orchestrator.config import DATA_DIR, WEB_HOST, WEB_PORT
from orchestrator.pdf_report import generate_detailed_pdf, generate_summary_pdf
from orchestrator.progress import label_for, percent_for
from orchestrator.queue import cancel_job, submit_job
from orchestrator.report import generate_report
from orchestrator.system_status import get_full_status

BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(title="Bug Bounty Automation Dashboard")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.mount("/evidence", StaticFiles(directory=str(DATA_DIR)), name="evidence")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def _job_progress(job: dict) -> dict:
    phase = job["phase"] if "phase" in job.keys() and job["phase"] else "queued"
    current = job["progress_current"] if "progress_current" in job.keys() else 0
    total = job["progress_total"] if "progress_total" in job.keys() else 0
    return {
        "phase": phase,
        "label": label_for(phase),
        "percent": percent_for(phase, current, total),
        "current": current,
        "total": total,
    }


def _screenshot_url(finding: dict) -> str | None:
    path = finding["screenshot_path"] if "screenshot_path" in finding.keys() else ""
    if not path:
        return None
    try:
        rel = Path(path).relative_to(DATA_DIR)
    except ValueError:
        return None
    return f"/evidence/{rel.as_posix()}"


@app.on_event("startup")
def startup():
    db.init_db()


@app.get("/")
def index(request: Request, status: str | None = None):
    jobs = [dict(j) for j in db.list_jobs(status=status)]
    for j in jobs:
        j["progress"] = _job_progress(j)
    status_counts = db.job_status_counts()
    sys_status = get_full_status()
    return templates.TemplateResponse(
        request, "index.html",
        {"jobs": jobs, "status_counts": status_counts, "sys_status": sys_status, "active_filter": status},
    )


@app.post("/scan")
async def scan(domain: str = Form(...), scope: str = Form("")):
    job_id = await submit_job(domain.strip(), scope)
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@app.post("/jobs/{job_id}/rescan")
async def rescan(job_id: int):
    job = db.get_job(job_id)
    if not job:
        return RedirectResponse("/", status_code=303)
    scope_text = job["scope_text"] if "scope_text" in job.keys() else ""
    new_job_id = await submit_job(job["target"], scope_text)
    return RedirectResponse(f"/jobs/{new_job_id}", status_code=303)


@app.post("/jobs/{job_id}/cancel")
def cancel(job_id: int):
    cancel_job(job_id)
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@app.get("/api/status")
def api_status():
    active_jobs = [dict(j) for j in db.list_jobs(status="running")] + [dict(j) for j in db.list_jobs(status="queued")]
    for j in active_jobs:
        j["progress"] = _job_progress(j)
    return {**get_full_status(), "active_jobs": active_jobs}


@app.get("/api/jobs/{job_id}/status")
def api_job_status(job_id: int):
    job = db.get_job(job_id)
    if not job:
        return {"error": "not found"}
    job = dict(job)
    job["progress"] = _job_progress(job)
    return job


@app.get("/jobs/{job_id}")
def job_detail(request: Request, job_id: int):
    job = db.get_job(job_id)
    if not job:
        return templates.TemplateResponse(request, "job.html", {"job": None})
    job = dict(job)
    job["progress"] = _job_progress(job)
    findings = db.list_findings(job_id=job_id)
    screenshot_urls = {f["id"]: _screenshot_url(f) for f in findings}
    chat_messages = db.list_chat_messages(job_id)
    manual_steps = {}
    for f in findings:
        raw = f["manual_steps"] if "manual_steps" in f.keys() else ""
        try:
            manual_steps[f["id"]] = json.loads(raw) if raw else []
        except (json.JSONDecodeError, TypeError):
            manual_steps[f["id"]] = [raw] if raw else []
    severity_counts = {}
    for f in findings:
        sev = (f["severity"] or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    return templates.TemplateResponse(
        request, "job.html",
        {
            "job": job, "findings": findings, "screenshot_urls": screenshot_urls,
            "chat_messages": chat_messages, "manual_steps": manual_steps,
            "severity_counts": severity_counts,
        },
    )


@app.post("/jobs/{job_id}/chat")
def job_chat(job_id: int, question: str = Form(...)):
    ask_about_job(job_id, question)  # stores both the question and answer in the DB
    return RedirectResponse(f"/jobs/{job_id}#chat", status_code=303)


@app.post("/findings/{finding_id}/verdict")
async def set_verdict(finding_id: int, verdict: str = Form(...), job_id: int = Form(...)):
    f = next((x for x in db.list_findings(limit=5000) if x["id"] == finding_id), None)
    if f:
        record_lesson_from_verdict(finding_id, f["kind"], f["title"], verdict)
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@app.get("/jobs/{job_id}/report")
def job_report(job_id: int):
    path = generate_report(job_id)
    return {"report_path": path}


@app.get("/jobs/{job_id}/report/summary.pdf")
def job_report_summary_pdf(job_id: int):
    path = generate_summary_pdf(job_id)
    if not path:
        return {"error": "job not found"}
    job = db.get_job(job_id)
    filename = f"{job['target']}_job{job_id}_summary.pdf"
    return FileResponse(path, media_type="application/pdf", filename=filename)


@app.get("/jobs/{job_id}/report/detailed.pdf")
def job_report_detailed_pdf(job_id: int):
    path = generate_detailed_pdf(job_id)
    if not path:
        return {"error": "job not found"}
    job = db.get_job(job_id)
    filename = f"{job['target']}_job{job_id}_detailed.pdf"
    return FileResponse(path, media_type="application/pdf", filename=filename)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=WEB_HOST, port=WEB_PORT, reload=False)
