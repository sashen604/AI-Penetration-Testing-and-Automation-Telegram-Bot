"""Maps pipeline phases to an approximate completion percentage.

AI triage dominates total runtime (~35s/finding vs seconds for the recon
tools), so the weighting below gives recon phases small fixed slices and
lets triage progress (current/total findings) drive most of the bar.
"""

PHASE_LABELS = {
    "queued": "Queued",
    "subfinder": "Enumerating subdomains",
    "httpx": "Probing live hosts",
    "katana": "Crawling",
    "gobuster": "Brute-forcing directories",
    "nuclei_scan": "Scanning for vulnerabilities (nuclei)",
    "dalfox_scan": "Scanning for XSS (dalfox)",
    "triaging": "AI triage",
    "aggregate_analysis": "AI risk analysis",
    "recon_suggestions": "AI manual-testing suggestions",
    "done": "Done",
    "failed": "Failed",
    "cancelled": "Cancelled",
}

# (phase, percent-at-start-of-phase)
_PHASE_FLOOR = [
    ("queued", 0), ("subfinder", 2), ("httpx", 8), ("katana", 14),
    ("gobuster", 20), ("nuclei_scan", 26), ("dalfox_scan", 30),
    ("triaging", 32), ("aggregate_analysis", 92), ("recon_suggestions", 96),
    ("done", 100), ("failed", 100), ("cancelled", 100),
]
_FLOOR = dict(_PHASE_FLOOR)


def percent_for(phase: str, current: int = 0, total: int = 0) -> int:
    base = _FLOOR.get(phase, 0)
    if phase == "triaging" and total > 0:
        span = _FLOOR["aggregate_analysis"] - _FLOOR["triaging"]
        return min(99, int(base + span * (current / total)))
    return base


def label_for(phase: str) -> str:
    return PHASE_LABELS.get(phase, phase)
