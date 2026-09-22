"""SQLite-backed knowledge base: jobs, findings, and the feedback loop.

This is the practical substitute for "training" the model: every finding
and every human verdict (true/false positive) is stored here. Before the
AI triages a new finding, we pull the most similar past verdicts back out
and put them in the prompt, so judgment improves over time without any
GPU training run.
"""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from orchestrator.config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    finished_at TEXT,
    summary TEXT DEFAULT '',
    risk_analysis TEXT DEFAULT '',
    scope_text TEXT DEFAULT '',
    phase TEXT DEFAULT 'queued',
    progress_current INTEGER DEFAULT 0,
    progress_total INTEGER DEFAULT 0,
    recon_suggestions TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER,
    target TEXT NOT NULL,
    tool TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    matched_url TEXT NOT NULL,
    evidence TEXT NOT NULL,
    verdict TEXT NOT NULL DEFAULT 'unverified',
    ai_summary TEXT DEFAULT '',
    ai_confidence REAL DEFAULT 0.0,
    screenshot_path TEXT DEFAULT '',
    description TEXT DEFAULT '',
    risk TEXT DEFAULT '',
    reasoning TEXT DEFAULT '',
    manual_steps TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);

CREATE TABLE IF NOT EXISTS reference_knowledge (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reference_category ON reference_knowledge(category);

CREATE TABLE IF NOT EXISTS lessons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_kind ON findings(kind);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        for stmt in (
            "ALTER TABLE findings ADD COLUMN screenshot_path TEXT DEFAULT ''",
            "ALTER TABLE jobs ADD COLUMN risk_analysis TEXT DEFAULT ''",
            "ALTER TABLE findings ADD COLUMN description TEXT DEFAULT ''",
            "ALTER TABLE findings ADD COLUMN risk TEXT DEFAULT ''",
            "ALTER TABLE findings ADD COLUMN reasoning TEXT DEFAULT ''",
            "ALTER TABLE findings ADD COLUMN manual_steps TEXT DEFAULT ''",
            "ALTER TABLE findings ADD COLUMN remediation TEXT DEFAULT ''",
            "ALTER TABLE jobs ADD COLUMN scope_text TEXT DEFAULT ''",
            "ALTER TABLE jobs ADD COLUMN phase TEXT DEFAULT 'queued'",
            "ALTER TABLE jobs ADD COLUMN progress_current INTEGER DEFAULT 0",
            "ALTER TABLE jobs ADD COLUMN progress_total INTEGER DEFAULT 0",
            "ALTER TABLE jobs ADD COLUMN recon_suggestions TEXT DEFAULT ''",
        ):
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass  # column already exists


def create_job(target: str, scope_text: str = "") -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO jobs (target, status, created_at, scope_text) VALUES (?, 'queued', ?, ?)",
            (target, datetime.now(timezone.utc).isoformat(), scope_text),
        )
        return cur.lastrowid


def set_risk_analysis(job_id: int, text: str):
    with get_conn() as conn:
        conn.execute("UPDATE jobs SET risk_analysis = ? WHERE id = ?", (text, job_id))


def set_recon_suggestions(job_id: int, text: str):
    with get_conn() as conn:
        conn.execute("UPDATE jobs SET recon_suggestions = ? WHERE id = ?", (text, job_id))


def set_phase(job_id: int, phase: str, current: int = 0, total: int = 0):
    with get_conn() as conn:
        conn.execute(
            "UPDATE jobs SET phase = ?, progress_current = ?, progress_total = ? WHERE id = ?",
            (phase, current, total, job_id),
        )


def update_job_status(job_id: int, status: str, summary: str = ""):
    with get_conn() as conn:
        finished_at = datetime.now(timezone.utc).isoformat() if status in ("done", "failed", "cancelled") else None
        conn.execute(
            "UPDATE jobs SET status = ?, finished_at = COALESCE(?, finished_at), summary = ? WHERE id = ?",
            (status, finished_at, summary, job_id),
        )


def list_jobs(limit: int = 50, status: str | None = None):
    with get_conn() as conn:
        if status:
            return conn.execute(
                "SELECT * FROM jobs WHERE status = ? ORDER BY id DESC LIMIT ?", (status, limit)
            ).fetchall()
        return conn.execute(
            "SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def get_job(job_id: int):
    with get_conn() as conn:
        return conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()


def add_finding(job_id: int, target: str, tool: str, kind: str, severity: str,
                 title: str, matched_url: str, evidence: str,
                 ai_summary: str = "", ai_confidence: float = 0.0) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO findings
               (job_id, target, tool, kind, severity, title, matched_url, evidence,
                verdict, ai_summary, ai_confidence, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unverified', ?, ?, ?)""",
            (job_id, target, tool, kind, severity, title, matched_url, evidence,
             ai_summary, ai_confidence, datetime.now(timezone.utc).isoformat()),
        )
        return cur.lastrowid


def set_triage_fields(finding_id: int, description: str, risk: str, reasoning: str,
                       manual_steps: list[str], remediation: str, ai_summary: str, ai_confidence: float):
    with get_conn() as conn:
        conn.execute(
            """UPDATE findings SET description=?, risk=?, reasoning=?, manual_steps=?,
               remediation=?, ai_summary=?, ai_confidence=? WHERE id=?""",
            (description, risk, reasoning, json.dumps(manual_steps), remediation,
             ai_summary, ai_confidence, finding_id),
        )


def set_screenshot(finding_id: int, path: str):
    with get_conn() as conn:
        conn.execute("UPDATE findings SET screenshot_path = ? WHERE id = ?", (path, finding_id))


def set_verdict(finding_id: int, verdict: str):
    with get_conn() as conn:
        conn.execute("UPDATE findings SET verdict = ? WHERE id = ?", (verdict, finding_id))


def list_findings(target: str | None = None, job_id: int | None = None, limit: int = 200):
    with get_conn() as conn:
        q = "SELECT * FROM findings WHERE 1=1"
        params = []
        if target:
            q += " AND target = ?"
            params.append(target)
        if job_id:
            q += " AND job_id = ?"
            params.append(job_id)
        q += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return conn.execute(q, params).fetchall()


def similar_past_verdicts(kind: str, title: str, limit: int = 5):
    """Pull past human-verified findings of the same kind to inform new triage."""
    with get_conn() as conn:
        return conn.execute(
            """SELECT title, matched_url, verdict, ai_summary FROM findings
               WHERE kind = ? AND verdict != 'unverified'
               ORDER BY id DESC LIMIT ?""",
            (kind, limit),
        ).fetchall()


def add_chat_message(job_id: int, role: str, content: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO chat_messages (job_id, role, content, created_at) VALUES (?, ?, ?, ?)",
            (job_id, role, content, datetime.now(timezone.utc).isoformat()),
        )
        return cur.lastrowid


def list_chat_messages(job_id: int, limit: int = 100):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM chat_messages WHERE job_id = ? ORDER BY id ASC LIMIT ?",
            (job_id, limit),
        ).fetchall()


def job_status_counts() -> dict:
    with get_conn() as conn:
        rows = conn.execute("SELECT status, COUNT(*) as n FROM jobs GROUP BY status").fetchall()
        return {r["status"]: r["n"] for r in rows}


def add_reference(category: str, title: str, content: str, source: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO reference_knowledge (category, title, content, source, created_at) VALUES (?, ?, ?, ?, ?)",
            (category, title, content, source, datetime.now(timezone.utc).isoformat()),
        )
        return cur.lastrowid


def clear_references(source: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM reference_knowledge WHERE source = ?", (source,))


def references_for_category(category: str, limit: int = 2):
    with get_conn() as conn:
        return conn.execute(
            "SELECT title, content FROM reference_knowledge WHERE category = ? ORDER BY RANDOM() LIMIT ?",
            (category, limit),
        ).fetchall()


def reference_category_counts():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT category, COUNT(*) as n FROM reference_knowledge GROUP BY category ORDER BY n DESC"
        ).fetchall()
        return [(r["category"], r["n"]) for r in rows]


def add_lesson(kind: str, note: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO lessons (kind, note, created_at) VALUES (?, ?, ?)",
            (kind, note, datetime.now(timezone.utc).isoformat()),
        )


def lessons_for(kind: str, limit: int = 5):
    with get_conn() as conn:
        return conn.execute(
            "SELECT note FROM lessons WHERE kind = ? ORDER BY id DESC LIMIT ?",
            (kind, limit),
        ).fetchall()
