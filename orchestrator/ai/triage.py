"""Calls the local Ollama model to triage a scanner finding."""
import json
import re

import ollama

from orchestrator import db
from orchestrator.ai.persona import (
    AGGREGATE_SYSTEM_PROMPT,
    RECON_SUGGESTIONS_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    build_aggregate_prompt,
    build_recon_suggestions_prompt,
    build_triage_prompt,
    match_reference_categories,
)
from orchestrator.config import OLLAMA_HOST, OLLAMA_MODEL

_client = ollama.Client(host=OLLAMA_HOST)

_FALLBACK_FIELDS = {
    "description": "",
    "risk": "",
    "verdict": "needs_manual_review",
    "confidence": 0.0,
    "reasoning": "",
    "manual_verification_steps": [],
    "remediation": "",
}


def _render_summary(fields: dict) -> str:
    """Human-readable rendering of the structured fields, kept for the web
    dashboard's simple text view and any place that just wants one blob."""
    steps = "\n".join(f"  {i}. {s}" for i, s in enumerate(fields["manual_verification_steps"], 1))
    return (
        f"Verdict: {fields['verdict']} (confidence {fields['confidence']:.2f})\n"
        f"Reasoning: {fields['reasoning']}\n\n"
        f"Manual verification steps:\n{steps}\n\n"
        f"Remediation: {fields['remediation']}"
    )


def triage_finding(finding: dict) -> dict:
    """finding: dict with tool/kind/severity/title/matched_url/evidence.

    Returns structured fields (description, risk, verdict, confidence,
    reasoning, manual_verification_steps, remediation) plus ai_summary (a
    rendered text blob) and ai_confidence, for callers that want one string.
    """
    similar = db.similar_past_verdicts(finding["kind"], finding["title"])
    lessons = db.lessons_for(finding["kind"])
    references = []
    for category in match_reference_categories(f"{finding['kind']} {finding['title']}"):
        references.extend(db.references_for_category(category, limit=1))
    user_prompt = build_triage_prompt(finding, similar, lessons, references)

    fields = dict(_FALLBACK_FIELDS)
    try:
        resp = _client.chat(
            model=OLLAMA_MODEL,
            format="json",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
        raw = json.loads(resp["message"]["content"])
        for key in _FALLBACK_FIELDS:
            if key in raw:
                fields[key] = raw[key]
        # defend against a model returning a string instead of a list, or a
        # non-numeric confidence -- never let a malformed field crash storage
        if isinstance(fields["manual_verification_steps"], str):
            fields["manual_verification_steps"] = [fields["manual_verification_steps"]]
        try:
            fields["confidence"] = float(fields["confidence"])
        except (TypeError, ValueError):
            fields["confidence"] = 0.5
    except Exception as e:
        fields["description"] = f"[AI triage unavailable: {e}]"
        fields["reasoning"] = "AI call failed -- raw finding requires manual review."
        fields["manual_verification_steps"] = ["AI unavailable -- review the raw scanner evidence manually."]

    return {
        **fields,
        "ai_summary": _render_summary(fields),
        "ai_confidence": fields["confidence"],
    }


def aggregate_analysis(target: str, findings: list[dict]) -> str:
    """One final AI pass over the whole finding set for a target: chains,
    priority ordering, systemic patterns. Runs once per job, not per finding."""
    if not findings:
        return "No findings to analyze."

    summary_lines = [
        f"- [{f['severity']}] {f['title']} (tool={f['tool']}, verdict={f['verdict']}, "
        f"ai_confidence={f['ai_confidence']:.2f}) @ {f['matched_url']}"
        for f in findings
    ]
    prompt = build_aggregate_prompt(target, summary_lines)

    try:
        resp = _client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": AGGREGATE_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        return resp["message"]["content"].strip()
    except Exception as e:
        return f"[Aggregate analysis unavailable: {e}]"


_STATIC_ASSET_RE = re.compile(
    r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|mp4|pdf)(\?|$)", re.IGNORECASE
)


def recon_suggestions(target: str, urls: list[str]) -> str:
    """Suggests manual testing angles from raw recon URLs/paths, grounded in
    the reference writeup corpus. Meant for the common case where nuclei/
    dalfox found nothing -- generic scanners don't catch business logic or
    access control issues, but the URL shapes themselves (product IDs,
    admin paths, etc.) are still useful signal for a human to chase.

    Static assets (.js/.css/images/etc) are filtered out before reaching
    the model -- they're not server-processed endpoints, and a small local
    model tends to nonsensically suggest injection-style techniques against
    them if they're left in the candidate list."""
    urls = [u for u in urls if not _STATIC_ASSET_RE.search(u)]
    if not urls:
        return "No recon surface to analyze."

    combined_text = " ".join(urls)
    categories = match_reference_categories(combined_text, max_categories=4)
    references = []
    for category in categories:
        references.extend(db.references_for_category(category, limit=2))

    prompt = build_recon_suggestions_prompt(target, urls, references)
    try:
        resp = _client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": RECON_SUGGESTIONS_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        return resp["message"]["content"].strip()
    except Exception as e:
        return f"[Recon suggestions unavailable: {e}]"


def record_lesson_from_verdict(finding_id: int, kind: str, title: str, human_verdict: str):
    """Called when the operator marks a finding true/false positive.

    Appends a short note to the lessons table so future triage of the same
    finding kind is calibrated by this feedback.
    """
    note = f"Finding '{title}' was marked {human_verdict} by the operator."
    db.add_lesson(kind, note)
    db.set_verdict(finding_id, human_verdict)
