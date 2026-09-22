# AI Penetration Testing and Automation Telegram Bot

A local, self-hosted bug bounty automation stack: recon → scanning → AI triage → PoC
screenshots → PDF reports, controllable from a web dashboard or a Telegram bot. Runs
entirely on your own machine — no cloud services, no paid APIs. The AI layer uses a
local Ollama model, not a hosted LLM.

## ⚠️ Authorization notice

Only run this against targets you are explicitly authorized to test — a bug bounty
program's in-scope assets, or a signed penetration testing engagement. Scanning
systems you don't have permission to test is illegal in most jurisdictions. The
default scope behavior (see "Scope" below) restricts scans to the domain you type
and its subdomains; you must not widen this beyond what you're authorized for.

## What it does

- **Recon**: subfinder, httpx, katana (domain-scoped crawling), gobuster
- **Scanning**: nuclei, dalfox, naabu + nmap (port scanning)
- **AI triage**: a local Ollama model reviews every finding (verdict, confidence,
  risk, manual verification steps, remediation) — grounded in your own past
  verdicts (a real feedback loop) and, optionally, a corpus of vulnerability
  writeups (see "Knowledge base" below)
- **PoC evidence**: automatic screenshot capture per finding
- **Reports**: PDF (summary + detailed, severity color-coded) and Markdown
- **Dashboards**: web UI with live scan progress, system/AI resource monitoring,
  and an AI chat scoped to a scan's findings; Telegram bot with the same
  capabilities

## Requirements

- Any Linux distro. Tested on Arch (Omarchy). Commands below cover Arch and
  Debian/Ubuntu; adapt for others.
- ~4GB+ RAM minimum (8GB+ recommended) to run a small local model comfortably.
- ~5GB disk for tools, templates, and the model.

## Installation

### 1. System packages

**Arch:**
```bash
sudo pacman -S --needed go base-devel nmap gobuster ollama chromium
```

**Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install -y golang-go build-essential nmap gobuster chromium-browser python3-venv git
curl -fsSL https://ollama.com/install.sh | sh
```

Start Ollama:
```bash
sudo systemctl enable --now ollama
```

### 2. Wordlist (seclists)

**Arch (AUR):**
```bash
yay -S seclists
```

**Debian/Ubuntu:**
```bash
sudo apt install seclists   # available on Kali; on plain Debian/Ubuntu, clone manually:
# sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

### 3. Recon/scan toolchain (Go tools)

```bash
export PATH="$PATH:$HOME/go/bin"   # add this to your ~/.bashrc too
for pkg in \
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
  "github.com/projectdiscovery/httpx/cmd/httpx@latest" \
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" \
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" \
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
  "github.com/projectdiscovery/katana/cmd/katana@latest" \
  "github.com/ffuf/ffuf/v2@latest" \
  "github.com/lc/gau/v2/cmd/gau@latest" \
  "github.com/tomnomnom/waybackurls@latest" \
  "github.com/tomnomnom/assetfinder@latest" \
  "github.com/sensepost/gowitness@latest" \
  "github.com/hahwul/dalfox/v2@latest" \
  "github.com/tomnomnom/anew@latest"; do
  go install -v "$pkg"
done

nuclei -update-templates
```

### 4. Pull the local AI model

```bash
ollama pull llama3.2:3b
```
(Any Ollama model works — set `OLLAMA_MODEL` in `.env` to match. A larger model
gives better triage reasoning at the cost of speed; 3B is a reasonable default
for 8-16GB RAM machines.)

### 5. Clone this repo and set up Python

```bash
git clone https://github.com/sashen604/AI-Penetration-Testing-and-Automation-Telegram-Bot.git
cd AI-Penetration-Testing-and-Automation-Telegram-Bot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 6. Configure

```bash
cp .env.example .env
```
Edit `.env` — see the Telegram bot section below for the two values you must set
before the bot will work. Everything else has a sane default.

---

## Setting up your own Telegram bot

**Do not reuse anyone else's bot token.** Each person running this project needs
their own bot, pointed only at their own Telegram account. Takes under 2 minutes:

1. In Telegram, open a chat with **[@BotFather](https://t.me/BotFather)**.
2. Send `/newbot`. Choose a display name, then a unique username ending in `bot`
   (e.g. `my_bugbounty_bot`).
3. BotFather replies with a token that looks like `123456789:AAExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`.
   Copy it.
4. Get your own numeric Telegram user ID: message **[@userinfobot](https://t.me/userinfobot)**,
   it replies immediately with your ID.
5. Open `.env` and set:
   ```
   TELEGRAM_BOT_TOKEN=<the token from step 3>
   TELEGRAM_ALLOWED_USER_IDS=<your numeric ID from step 4>
   ```
   Setting `TELEGRAM_ALLOWED_USER_IDS` matters: leaving it blank lets **anyone**
   who finds your bot's username issue scan commands through it.
6. Treat the token like a password — never commit it, paste it in chat, or share
   it. `.env` is already gitignored by this project. If a token ever leaks,
   message @BotFather with `/revoke` immediately to invalidate it, then generate
   a new one and update `.env`.

---

## Running

**Web dashboard** (recommended starting point):
```bash
source venv/bin/activate
python web/app.py
```
Open `http://127.0.0.1:8787`.

**Telegram bot:**
```bash
source venv/bin/activate
python bot/telegram_bot.py
```
Then message your bot `/start`.

**CLI** (no dashboard/bot needed):
```bash
source venv/bin/activate
python -m orchestrator.cli scan example.com
python -m orchestrator.cli jobs
python -m orchestrator.cli findings example.com
```

## Scope

By default, a scan with no scope specified is restricted to the target domain
and its subdomains — it will not follow crawled links off-site. To narrow or
widen this explicitly, provide scope rules (one per line, in the web form, the
`/scope` Telegram command, or a `--scope <file>` for the CLI):
```
*.example.com
!staging.example.com
```

## Knowledge base (optional): grounding AI suggestions in real writeups

When automated scanners find little or nothing — common against a deliberately
built or well-configured app rather than a misconfigured real target — the AI
can still suggest manual testing angles, grounded in a corpus of vulnerability
writeups matched against the URLs/parameters your scan actually discovered.
This ships empty; point it at any writeup collection organized as
`category/lab-name/*.md`:

```bash
git clone https://github.com/sh3bu/Portswigger_labs.git knowledge_sources/Portswigger_labs
source venv/bin/activate
python -m orchestrator.knowledge_ingest \
  knowledge_sources/Portswigger_labs \
  https://github.com/sh3bu/Portswigger_labs.git
```

This is retrieval into the AI's prompt context, not model fine-tuning — no GPU
or training run required, and you can re-run ingestion any time to refresh it.

## Known limitations

- **AI triage is sequential and slow** on CPU-only hardware — roughly 30-60s per
  finding with a 3B model. A scan with many findings will take a while in the
  triage phase specifically.
- **Small local models reason imprecisely at times.** Verdicts, risk assessments,
  and manual-testing suggestions are a strong starting point, not ground truth —
  review before acting on them, especially before reporting anything to a
  program.
- **sqlmap is deliberately not included/automated.** Destructive-capable tools
  stay manual-trigger-only by design.
- This project does not automate exploitation (data extraction, shell access,
  privilege escalation). It automates recon, scanning, triage, and PoC
  verification — the line where "prove it's real" stops and "actually exploit
  it" begins is intentional and enforced in the AI's own system prompts.

## Project structure

```
orchestrator/       Core pipeline: tool wrappers, DB, AI triage, PDF/report generation
  ai/                Persona/prompts, triage, chat, aggregate analysis, status checks
  pdf_templates/     Jinja2 + WeasyPrint templates for PDF reports
web/                 FastAPI dashboard
bot/                 Telegram bot
data/                Scan output (gitignored) — evidence, screenshots, reports per target
knowledge_sources/   Ingested writeup repos (gitignored, clone your own)
```
