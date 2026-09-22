"""Telegram control plane for the bug bounty pipeline.

Commands:
  /scan <domain>            - full pipeline: recon+vuln scan+AI triage
  /subenum <domain>         - subdomain enumeration only (subfinder+httpx)
  /portscan <host>          - port scan only (naabu+nmap)
  /webscan <url>            - vuln scan a single URL (nuclei+AI triage)
  /dirscan <url>            - directory brute-force a single URL (gobuster)
  /scope <rules...>         - set scope rules for the NEXT /scan or /subenum
                               or /portscan, one rule per line, e.g.:
                               /scope *.example.com
                                     !staging.example.com
  /status <job_id>          - check job status
  /jobs                     - list recent jobs
  /findings <job_id>        - list findings for a job

Only user IDs in TELEGRAM_ALLOWED_USER_IDS (see .env) may issue commands.
Set TELEGRAM_BOT_TOKEN in .env (create the bot via @BotFather first).
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import logging

from dotenv import load_dotenv
from telegram import BotCommand, Update
from telegram.error import NetworkError, TimedOut
from telegram.ext import Application, CommandHandler, ContextTypes

load_dotenv()

from orchestrator import db
from orchestrator.config import TELEGRAM_ALLOWED_USER_IDS, TELEGRAM_BOT_TOKEN
from orchestrator.pipeline import (
    run_dir_scan_standalone,
    run_port_scan_standalone,
    run_subdomain_enum,
    run_web_vuln_scan,
)
from orchestrator.queue import submit_job

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("telegram_bot")

_pending_scope: dict[int, str] = {}

TELEGRAM_MAX_LEN = 4000  # stay under Telegram's 4096-char message limit

COMMANDS = [
    BotCommand("start", "About this tool"),
    BotCommand("scan", "Full pipeline: recon + vuln scan + AI triage"),
    BotCommand("subenum", "Subdomain enumeration only (subfinder+httpx)"),
    BotCommand("portscan", "Port scan only (naabu+nmap)"),
    BotCommand("webscan", "Vuln scan a single URL (nuclei+AI triage)"),
    BotCommand("dirscan", "Directory brute-force a single URL (gobuster)"),
    BotCommand("scope", "Set scope rules for your next scan"),
    BotCommand("jobs", "List recent scan jobs"),
    BotCommand("status", "Check a job's status"),
    BotCommand("findings", "List findings for a job"),
]


def _authorized(update: Update) -> bool:
    if not TELEGRAM_ALLOWED_USER_IDS:
        return True  # open mode if no allowlist configured; tighten via .env
    return update.effective_user and update.effective_user.id in TELEGRAM_ALLOWED_USER_IDS


async def _safe_reply(update: Update, text: str, retries: int = 3, **kwargs):
    """This environment has shown recurring transient network failures
    (TimedOut/NetworkError) specifically on the outbound reply, after the
    inbound command was already received -- which looks like total
    silence to the operator even though the bot is alive and working.
    Retry a few times with backoff before giving up."""
    for attempt in range(retries):
        try:
            return await update.message.reply_text(text, **kwargs)
        except (TimedOut, NetworkError) as e:
            if attempt == retries - 1:
                log.error("reply failed after %d attempts: %s", retries, e)
                raise
            log.warning("reply attempt %d/%d failed (%s), retrying...", attempt + 1, retries, e)
            await asyncio.sleep(2 * (attempt + 1))


async def _reply_chunked(update: Update, text: str):
    for i in range(0, len(text), TELEGRAM_MAX_LEN):
        await _safe_reply(update, text[i:i + TELEGRAM_MAX_LEN])


async def _run_background_scan(update: Update, label: str, coro):
    try:
        result = await coro
        await _reply_chunked(update, f"✅ {label} done:\n\n{result}")
    except Exception as e:
        log.exception("%s failed", label)
        try:
            await _safe_reply(update, f"❌ {label} failed: {e}")
        except (TimedOut, NetworkError):
            pass  # already logged above; don't let a reply failure mask the real error


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await _safe_reply(update, 
        "🛡️ *Bug Bounty Automation*\n"
        "_Recon → Scan → AI Triage → PoC → Report_\n\n"
        "I run the real recon/scan toolchain (subfinder, httpx, katana, "
        "gobuster, nuclei, dalfox, naabu, nmap) against targets you're "
        "authorized to test, then a local AI triages findings, screenshots "
        "PoCs, and writes you a report. Everything stays on this machine.\n\n"
        "*Full pipeline*\n"
        "`/scan example.com` — recon + vuln scan + AI triage + PoC\n\n"
        "*One thing at a time*\n"
        "`/subenum example.com` — just subdomains\n"
        "`/portscan example.com` — just open ports (naabu+nmap)\n"
        "`/webscan https://example.com/page` — just nuclei on one URL\n"
        "`/dirscan https://example.com` — just directory brute-force\n\n"
        "*Scope & tracking*\n"
        "`/scope <rules>` — restrict the next scan\n"
        "`/jobs` `/status <id>` `/findings <id>`\n\n"
        "⚠️ Only scan targets you have explicit authorization for "
        "(bug bounty program scope or signed pentest engagement).",
        parse_mode="Markdown",
    )
    try:
        await update.message.reply_dice(emoji="🎯")
    except Exception:
        pass  # cosmetic only, never block the real welcome message on this


async def scope_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _authorized(update):
        return await _safe_reply(update, "Not authorized.")
    text = update.message.text.partition(" ")[2]
    _pending_scope[update.effective_user.id] = text
    await _safe_reply(update, f"Scope set for your next /scan:\n{text or '(none)'}")


async def scan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _authorized(update):
        return await _safe_reply(update, "Not authorized.")
    if not context.args:
        return await _safe_reply(update, "Usage: /scan example.com")
    domain = context.args[0].strip()
    scope_text = _pending_scope.pop(update.effective_user.id, "")
    job_id = await submit_job(domain, scope_text)
    await _safe_reply(update, 
        f"Queued job #{job_id} for {domain}. I'll message you when it's done.\n"
        f"Check anytime with /status {job_id}"
    )
    context.application.create_task(_watch_job(update, job_id))


async def subenum_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _authorized(update):
        return await _safe_reply(update, "Not authorized.")
    if not context.args:
        return await _safe_reply(update, "Usage: /subenum example.com")
    domain = context.args[0].strip()
    scope_text = _pending_scope.pop(update.effective_user.id, "")
    await _safe_reply(update, f"🔎 Enumerating subdomains for {domain}...")
    context.application.create_task(
        _run_background_scan(update, f"Subdomain enum for {domain}", run_subdomain_enum(domain, scope_text))
    )


async def portscan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _authorized(update):
        return await _safe_reply(update, "Not authorized.")
    if not context.args:
        return await _safe_reply(update, "Usage: /portscan example.com")
    host = context.args[0].strip()
    scope_text = _pending_scope.pop(update.effective_user.id, "")
    await _safe_reply(update, f"🔌 Port scanning {host} (naabu+nmap, this takes a bit)...")
    context.application.create_task(
        _run_background_scan(update, f"Port scan for {host}", run_port_scan_standalone(host, scope_text))
    )


async def webscan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _authorized(update):
        return await _safe_reply(update, "Not authorized.")
    if not context.args:
        return await _safe_reply(update, "Usage: /webscan https://example.com/page")
    url = context.args[0].strip()
    await _safe_reply(update, f"🩻 Running nuclei + AI triage on {url}...")
    context.application.create_task(
        _run_background_scan(update, f"Web vuln scan for {url}", run_web_vuln_scan(url))
    )


async def dirscan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _authorized(update):
        return await _safe_reply(update, "Not authorized.")
    if not context.args:
        return await _safe_reply(update, "Usage: /dirscan https://example.com")
    url = context.args[0].strip()
    await _safe_reply(update, f"📂 Brute-forcing directories on {url}...")
    context.application.create_task(
        _run_background_scan(update, f"Dir scan for {url}", run_dir_scan_standalone(url))
    )


async def _watch_job(update: Update, job_id: int, interval: int = 15):
    while True:
        await asyncio.sleep(interval)
        job = db.get_job(job_id)
        if job and job["status"] in ("done", "failed"):
            await _safe_reply(update, 
                f"Job #{job_id} ({job['target']}) {job['status']}.\n{job['summary']}"
            )
            return


async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await _safe_reply(update, "Usage: /status <job_id>")
    job = db.get_job(int(context.args[0]))
    if not job:
        return await _safe_reply(update, "Job not found.")
    await _safe_reply(update, f"#{job['id']} {job['target']} — {job['status']}\n{job['summary']}")


async def jobs_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    jobs = db.list_jobs(limit=10)
    if not jobs:
        return await _safe_reply(update, "No jobs yet.")
    lines = [f"#{j['id']} {j['status']:<8} {j['target']}" for j in jobs]
    await _safe_reply(update, "\n".join(lines))


async def findings_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await _safe_reply(update, "Usage: /findings <job_id>")
    findings = db.list_findings(job_id=int(context.args[0]))
    if not findings:
        return await _safe_reply(update, "No findings.")
    lines = [f"[{f['severity']}] {f['title']} ({f['verdict']}) -> {f['matched_url']}" for f in findings[:20]]
    await _safe_reply(update, "\n".join(lines))


async def _post_init(app: Application):
    await app.bot.set_my_commands(COMMANDS)
    log.info("Registered %d commands with Telegram (shown on '/' menu)", len(COMMANDS))


async def _on_error(update, context: ContextTypes.DEFAULT_TYPE):
    """Replaces PTB's default 'No error handlers are registered' log spam
    with something actionable, and tries to let the operator know rather
    than failing silently from their point of view."""
    log.error("update %s caused error: %s", update, context.error)
    if isinstance(update, Update) and update.message:
        try:
            await _safe_reply(update, f"⚠️ Something went wrong handling that: {context.error}", retries=1)
        except (TimedOut, NetworkError):
            pass


def main():
    if not TELEGRAM_BOT_TOKEN:
        raise SystemExit("Set TELEGRAM_BOT_TOKEN in bugbounty/.env first (see .env.example)")
    db.init_db()
    app = (
        Application.builder()
        .token(TELEGRAM_BOT_TOKEN)
        .post_init(_post_init)
        # This environment has shown recurring multi-second network latency
        # to Telegram's API; PTB's defaults (~5s) are too tight for that and
        # were causing replies to silently fail after the command was
        # already received. Give real headroom.
        .connect_timeout(20)
        .read_timeout(20)
        .write_timeout(20)
        .pool_timeout(20)
        .build()
    )
    app.add_error_handler(_on_error)
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scope", scope_cmd))
    app.add_handler(CommandHandler("scan", scan_cmd))
    app.add_handler(CommandHandler("subenum", subenum_cmd))
    app.add_handler(CommandHandler("portscan", portscan_cmd))
    app.add_handler(CommandHandler("webscan", webscan_cmd))
    app.add_handler(CommandHandler("dirscan", dirscan_cmd))
    app.add_handler(CommandHandler("status", status_cmd))
    app.add_handler(CommandHandler("jobs", jobs_cmd))
    app.add_handler(CommandHandler("findings", findings_cmd))
    log.info("Bot starting...")
    app.run_polling()


if __name__ == "__main__":
    main()
