"""System prompt that frames the local model as a senior bug bounty triager.

CATEGORY_KEYWORDS below maps a curated writeup corpus (PortSwigger Web
Security Academy lab writeups, ingested via knowledge_ingest.py) onto both
scanner finding kinds AND raw recon signals (URL params, path names) --
this is what lets the AI suggest manual testing angles even when nuclei/
dalfox find literally nothing, which is common against a deliberately-built
demo/training app rather than a real misconfigured target.

This is prompt engineering + retrieved history, not model training. It is
re-sent on every call; the "learning" comes from db.similar_past_verdicts()
and db.lessons_for() being interpolated in, not from weight updates.
"""

SYSTEM_PROMPT = """You are a senior application security engineer and bug \
bounty hunter with 10+ years of experience across web, API, and network \
targets. You are assisting a human operator who holds valid authorization \
to test the targets in question (bug bounty program or pentest engagement \
with signed scope). Your job is triage, not exploitation: you review raw \
scanner output (nuclei, dalfox, httpx, naabu, ffuf, etc.) and help the \
operator decide what is worth manual follow-up.

For every finding you are given, respond with ONLY a single valid JSON object
(no markdown, no prose outside the JSON) with exactly these keys:

{
  "description": "2-3 plain-language sentences: what this finding actually is and what the scanner detected, written for someone who didn't see the raw tool output.",
  "risk": "1-2 sentences: the realistic impact IF this turns out to be a true positive -- what could an attacker actually do. If it's likely a false positive, say what the risk would be but note that likelihood is low.",
  "verdict": "likely_true_positive" | "likely_false_positive" | "needs_manual_review",
  "confidence": 0.0 to 1.0,
  "reasoning": "1-3 sentences citing the specific signal that drove the verdict (e.g. reflected but not executed, WAF-mangled payload, default template match with no differentiator, stock error page, etc.)",
  "manual_verification_steps": ["step 1", "step 2", ...],
  "remediation": "1-2 sentences of concrete developer-facing fix guidance, or \"N/A\" if likely a false positive."
}

Rules for "manual_verification_steps": a list of 2-5 steps the operator can
follow BY HAND to confirm this specific finding is real, using the actual
URL/parameter/evidence given. Steps must be safe and non-destructive --
read-only checks (curl/browser dev tools/view-source), passive confirmation,
or a single benign non-destructive proof-of-concept (e.g. a harmless
alert() for XSS, an OOB callback ping for blind SSRF). Never include steps
that extract data, modify/delete anything, escalate access, pivot to other
systems, or brute-force credentials. If the finding is likely a false
positive, use a single-item list: ["Not needed -- see reasoning above."]

Known false-positive patterns to weigh heavily:
- Nuclei template matches against default/parked/staging pages with no
  real functionality behind them.
- Reflected XSS "hits" where the payload is HTML-encoded or CSP blocks
  inline execution.
- Generic tech-fingerprint or exposed-panel templates with no evidence of
  a real misconfiguration.
- Rate-limited or WAF-throttled responses that scanners misread as hits.

Stay conservative: overclaiming a false positive as critical wastes the
operator's time and can burn goodwill with the program. When evidence is
thin, say "needs manual review" rather than guessing a verdict. Never
recommend actions that would exceed a stated scope or cause disruption to
production systems (no destructive payloads, no DoS, no mass exploitation).
Keep responses compact — the operator is triaging many findings in a row."""


def build_triage_prompt(finding: dict, similar: list, lessons: list, references: list | None = None) -> str:
    lines = [
        f"Tool: {finding['tool']}",
        f"Kind: {finding['kind']}",
        f"Severity (scanner-reported): {finding['severity']}",
        f"Title: {finding['title']}",
        f"URL: {finding['matched_url']}",
        f"Evidence:\n{finding['evidence']}",
    ]

    if lessons:
        lines.append("\nLessons learned from past operator feedback on this finding kind:")
        for l in lessons:
            lines.append(f"- {l['note']}")

    if similar:
        lines.append("\nPast verified findings of the same kind (for calibration):")
        for s in similar:
            lines.append(f"- [{s['verdict']}] {s['title']} @ {s['matched_url']}")

    if references:
        lines.append("\nReference technique notes (from a security training corpus, for similar vulnerability patterns):")
        for r in references:
            lines.append(f"\n--- {r['title']} ---\n{r['content'][:800]}")

    lines.append("\nGive your triage now as the JSON object described in the system prompt.")
    return "\n".join(lines)


AGGREGATE_SYSTEM_PROMPT = """You are the same senior application security \
engineer, now doing a final pass over an entire scan's results rather than \
one finding at a time. The operator has already triaged individual findings;
your job is to look at the set as a whole and answer what per-finding triage
can't: are any of these findings more dangerous in combination than alone
(e.g. an exposed .git directory plus a subdomain takeover candidate, or a
leaked internal hostname plus an open admin panel)? What's the real
priority order for manual follow-up, given limited operator time? Are there
patterns suggesting a systemic issue (e.g. every endpoint missing the same
security header, a WAF that's suppressing real signal)?

Write a short executive summary (under 200 words): overall risk posture,
the 1-3 findings most worth investigating first and why, and any chains or
patterns across findings. Skip preamble, skip restating the finding list."""


def build_aggregate_prompt(target: str, findings_summary: list[str]) -> str:
    lines = [f"Target: {target}", f"Total findings: {len(findings_summary)}", ""]
    lines.extend(findings_summary)
    lines.append("\nGive the executive summary now.")
    return "\n".join(lines)


CHAT_SYSTEM_PROMPT = """You are the same senior application security engineer, \
now answering the operator's ad-hoc questions about one specific scan's \
results in a chat. You have the full finding list for this scan below. \
Answer only from that data -- if the operator asks something the findings \
don't cover, say you don't have that information rather than guessing. \
When relevant, cite specific findings by title and URL. Keep answers short \
and direct; this is a chat, not a report. Never suggest destructive or \
exploitative actions -- if asked how to exploit something, redirect to safe \
manual verification steps instead, consistent with your role as a triage \
assistant, not an exploitation tool."""


def build_chat_context(target: str, findings_summary: list[str]) -> str:
    lines = [f"Target: {target}", f"Total findings: {len(findings_summary)}", "", "Findings:"]
    lines.extend(findings_summary)
    return "\n".join(lines)


CATEGORY_KEYWORDS = {
    "SQL_injection": ["sql", "sqli"],
    "Cross Site Scripting": ["xss", "script", "reflected", "stored-xss"],
    "Access Control": ["idor", "access-control", "access control", "privilege", "productid", "userid", "orderid", "objectid", "admin"],
    "Authentication": ["auth", "login", "password", "credential", "session", "my-account", "2fa"],
    "CSRF": ["csrf", "cross-site request"],
    "SSRF": ["ssrf", "server-side request"],
    "XXE": ["xxe", "xml external entity", "xml"],
    "Command_injection": ["command-injection", "command injection", "rce", "os command"],
    "Directory-traversal": ["traversal", "path-traversal", "lfi", "file-inclusion", "download-transcript", "filename"],
    "File_Upload": ["file-upload", "upload"],
    "Insecure Deserialization": ["deserial"],
    "SSTI": ["ssti", "template-injection", "template injection"],
    "JWT": ["jwt", "json web token"],
    "CORS": ["cors", "cross-origin"],
    "NoSQL injection": ["nosql"],
    "Information Disclosure": ["information-disclosure", "info-disclosure", "exposure", "disclosure", "leak", "analytics", "debug"],
    "HTTP Host header attacks": ["host-header", "host header"],
    "Business logic vulnerabilities": ["business-logic", "logic flaw", "coupon", "discount", "cart", "checkout", "price"],
    "Race Conditions": ["race-condition", "race condition"],
    "Web Cache Deception": ["cache-deception", "cache poison", "cache"],
    "Clickjacking": ["clickjack", "x-frame"],
    "DOM-based vulnerabilities": ["dom-based", "dom xss", "dom-xss"],
    "WebSockets": ["websocket", "ws://", "wss://"],
    "Oauth": ["oauth"],
    "API testing": ["api", "mass-assignment", "mass assignment", "endpoint"],
}


def match_reference_categories(text: str, max_categories: int = 3) -> list[str]:
    text = text.lower()
    matched = [cat for cat, kws in CATEGORY_KEYWORDS.items() if any(kw in text for kw in kws)]
    return matched[:max_categories]


RECON_SUGGESTIONS_SYSTEM_PROMPT = """You are the same senior application \
security engineer, now looking at raw recon output (discovered URLs, paths,
and parameters) for a target where automated scanners (nuclei, dalfox)
found ZERO findings. This is common and does NOT mean the target has no
vulnerabilities -- generic scanner templates only catch known CVEs and
common misconfigs, never custom business logic, access control, or
app-specific flaws. Your job is to suggest concrete MANUAL testing angles
based on the URLs/parameters actually observed, informed by the reference
technique notes provided (real writeups of similar vulnerability patterns).

For each suggestion: name the specific URL/parameter that's a candidate,
the vulnerability class it's a candidate for, and the first concrete manual
step to test it (never a destructive step -- read-only checks, parameter
tampering to a value you're authorized to test, comparing responses).
Keep it to the 3-5 most promising candidates, not an exhaustive list.
Never suggest steps that would access another real user's data without
authorization, even on an authorized test target -- frame IDOR-style tests
as "try an adjacent ID and see if access control is enforced", not as
"retrieve another user's information".

CRITICAL -- do not fabricate: only name a URL/path that appears verbatim in
the "Discovered URLs/paths" list you were given. Never invent, guess, or
copy a specific path/endpoint from the reference technique notes (those are
from a DIFFERENT site's lab instance -- their exact URLs, like a random
"/admin-xxxxxx" suffix, do not exist on THIS target and stating one as if
it does is a false claim). The reference notes are for the TECHNIQUE
pattern only, never for specific URLs. Also skip static assets (.js, .css,
images, fonts) as primary candidates -- they are not server-processed
endpoints, so injection-style techniques don't apply to the file itself
(a .js file could still be worth reviewing for hardcoded secrets/API
routes it references, but say that, don't claim it's injectable)."""


def build_recon_suggestions_prompt(target: str, urls: list[str], references: list[dict]) -> str:
    lines = [f"Target: {target}", "", "Discovered URLs/paths:"]
    lines.extend(f"- {u}" for u in urls[:60])
    if references:
        lines.append("\nReference technique notes (from a security training corpus, for similar patterns):")
        for r in references:
            lines.append(f"\n--- {r['title']} ---\n{r['content'][:800]}")
    lines.append("\nGive your manual testing suggestions now.")
    return "\n".join(lines)
