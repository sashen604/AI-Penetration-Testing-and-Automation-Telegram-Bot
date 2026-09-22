"""Central configuration for the bug bounty automation stack."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
TARGETS_DIR = DATA_DIR / "targets"
DB_PATH = DATA_DIR / "knowledge_base.sqlite3"

GO_BIN = str(Path.home() / "go" / "bin")

TOOL_PATHS = {
    "subfinder": f"{GO_BIN}/subfinder",
    "httpx": f"{GO_BIN}/httpx",
    "dnsx": f"{GO_BIN}/dnsx",
    "naabu": f"{GO_BIN}/naabu",
    "nuclei": f"{GO_BIN}/nuclei",
    "katana": f"{GO_BIN}/katana",
    "ffuf": f"{GO_BIN}/ffuf",
    "gau": f"{GO_BIN}/gau",
    "waybackurls": f"{GO_BIN}/waybackurls",
    "assetfinder": f"{GO_BIN}/assetfinder",
    "gowitness": f"{GO_BIN}/gowitness",
    "dalfox": f"{GO_BIN}/dalfox",
    "nmap": "/usr/bin/nmap",
    "gobuster": "/usr/bin/gobuster",
}

GOBUSTER_WORDLIST = os.environ.get(
    "GOBUSTER_WORDLIST",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
)
GOBUSTER_THREADS = int(os.environ.get("GOBUSTER_THREADS", "20"))
# Cap how many live hosts get directory-brute-forced per scan; gobuster
# against every subdomain of a large program would take forever and hammer
# the target far harder than the recon steps do.
GOBUSTER_MAX_HOSTS = int(os.environ.get("GOBUSTER_MAX_HOSTS", "5"))

# Ollama model used for triage/summarization. Pull this before first run:
#   ollama pull llama3.2:3b
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
# A stuck Ollama/llama-server request (observed: a hang that ran for 10+
# hours, exhausted system RAM via swap, and took the web app down with it)
# must never block forever. These bound every call; a genuine timeout is
# always caught and handled as a normal failure, never left to hang.
OLLAMA_REQUEST_TIMEOUT = int(os.environ.get("OLLAMA_REQUEST_TIMEOUT", "180"))
OLLAMA_HEALTHCHECK_TIMEOUT = int(os.environ.get("OLLAMA_HEALTHCHECK_TIMEOUT", "10"))

# Telegram bot token, set via environment or .env file. Never commit this.
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_ALLOWED_USER_IDS = [
    int(x) for x in os.environ.get("TELEGRAM_ALLOWED_USER_IDS", "").split(",") if x.strip()
]

# Web dashboard
WEB_HOST = os.environ.get("WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.environ.get("WEB_PORT", "8787"))

# Rate limiting / politeness defaults for scans
DEFAULT_RATE_LIMIT = int(os.environ.get("SCAN_RATE_LIMIT", "150"))  # requests/sec cap for nuclei/httpx
NUCLEI_SEVERITY = os.environ.get("NUCLEI_SEVERITY", "info,low,medium,high,critical")

# Crawl safety caps. katana without domain scoping will happily follow links
# off-target (CDNs, social links, analytics) which is both a scope violation
# risk and a resource sink -- keep it locked to the root domain and capped.
KATANA_MAX_DEPTH = int(os.environ.get("KATANA_MAX_DEPTH", "2"))
KATANA_CONCURRENCY = int(os.environ.get("KATANA_CONCURRENCY", "10"))
MAX_CRAWL_URLS = int(os.environ.get("MAX_CRAWL_URLS", "500"))
MAX_DALFOX_URLS = int(os.environ.get("MAX_DALFOX_URLS", "100"))

for d in (DATA_DIR, TARGETS_DIR):
    d.mkdir(parents=True, exist_ok=True)
