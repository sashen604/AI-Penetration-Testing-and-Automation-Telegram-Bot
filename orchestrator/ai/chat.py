"""Chat interface for asking the local AI about a specific scan's findings."""
import ollama

from orchestrator import db
from orchestrator.ai.persona import CHAT_SYSTEM_PROMPT, build_chat_context
from orchestrator.config import OLLAMA_HOST, OLLAMA_MODEL

_client = ollama.Client(host=OLLAMA_HOST)

MAX_HISTORY_TURNS = 6  # keep the prompt from growing unbounded over a long chat


def ask_about_job(job_id: int, question: str) -> str:
    job = db.get_job(job_id)
    if not job:
        return "That job doesn't exist."

    findings = db.list_findings(job_id=job_id, limit=1000)
    summary_lines = [
        f"- [{f['severity']}] {f['title']} (tool={f['tool']}, verdict={f['verdict']}, "
        f"ai_confidence={f['ai_confidence']:.2f}) @ {f['matched_url']}"
        for f in findings
    ]
    context = build_chat_context(job["target"], summary_lines)
    if job["risk_analysis"]:
        context += f"\n\nExecutive summary from earlier analysis:\n{job['risk_analysis']}"

    history = db.list_chat_messages(job_id, limit=MAX_HISTORY_TURNS * 2)
    messages = [{"role": "system", "content": CHAT_SYSTEM_PROMPT + "\n\n" + context}]
    for m in history:
        messages.append({"role": m["role"], "content": m["content"]})
    messages.append({"role": "user", "content": question})

    db.add_chat_message(job_id, "user", question)
    try:
        resp = _client.chat(model=OLLAMA_MODEL, messages=messages)
        answer = resp["message"]["content"].strip()
    except Exception as e:
        answer = f"[AI unavailable: {e}]"
    db.add_chat_message(job_id, "assistant", answer)
    return answer
