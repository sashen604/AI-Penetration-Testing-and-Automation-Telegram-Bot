"""Async pipeline: recon -> probe -> scan -> triage -> report.

Every step shells out to a ProjectDiscovery-style CLI tool and writes raw
output into the target's evidence folder. Findings from nuclei/dalfox are
parsed, stored in the knowledge base, and sent through AI triage.
"""
import asyncio
import json
import logging

from urllib.parse import urlparse

from orchestrator import db
from orchestrator.ai.triage import aggregate_analysis, recon_suggestions, triage_finding
from orchestrator.config import (
    DEFAULT_RATE_LIMIT,
    GOBUSTER_MAX_HOSTS,
    GOBUSTER_THREADS,
    GOBUSTER_WORDLIST,
    KATANA_CONCURRENCY,
    KATANA_MAX_DEPTH,
    MAX_CRAWL_URLS,
    MAX_DALFOX_URLS,
    NUCLEI_SEVERITY,
    TOOL_PATHS,
)
from orchestrator.evidence import capture_screenshot
from orchestrator.scope import Scope
from orchestrator.storage import raw_path, target_dir

log = logging.getLogger("pipeline")


async def _run(cmd: list[str], stdin_data: str | None = None, timeout: int = 900) -> tuple[str, str, int]:
    """Run a tool subprocess with a hard timeout. A stuck/runaway tool (e.g.
    dalfox grinding through too many URLs) kills the pipeline job silently
    otherwise -- better to time out, log it, and let the pipeline continue
    with whatever downstream steps still make sense."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    input_bytes = stdin_data.encode() if stdin_data is not None else None
    try:
        out, err = await asyncio.wait_for(proc.communicate(input=input_bytes), timeout=timeout)
        return out.decode(errors="replace"), err.decode(errors="replace"), proc.returncode
    except asyncio.TimeoutError:
        log.warning("command timed out after %ss: %s", timeout, " ".join(cmd[:2]))
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return "", f"timed out after {timeout}s", -1
    except asyncio.CancelledError:
        # job was cancelled by the operator -- kill the subprocess, then let
        # the cancellation keep propagating up through the pipeline
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        raise


async def run_subfinder(root_domain: str, target_label: str) -> list[str]:
    cmd = [TOOL_PATHS["subfinder"], "-d", root_domain, "-silent"]
    out, err, rc = await _run(cmd)
    subs = [l.strip() for l in out.splitlines() if l.strip()]
    raw_path(target_label, "subfinder.txt").write_text(out)
    log.info("subfinder: %d subdomains for %s", len(subs), root_domain)
    return subs


async def run_httpx(hosts: list[str], target_label: str) -> list[dict]:
    if not hosts:
        return []
    cmd = [TOOL_PATHS["httpx"], "-silent", "-json", "-rate-limit", str(DEFAULT_RATE_LIMIT)]
    out, err, rc = await _run(cmd, stdin_data="\n".join(hosts))
    raw_path(target_label, "httpx.jsonl").write_text(out)
    results = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    log.info("httpx: %d live hosts", len(results))
    return results


async def run_nuclei(urls: list[str], target_label: str) -> tuple[list[dict], bool]:
    """Returns (findings, timed_out). timed_out=True means the scan was cut
    off mid-run -- 0 findings in that case means "incomplete", not "clean"."""
    if not urls:
        return [], False
    cmd = [
        TOOL_PATHS["nuclei"], "-silent", "-jsonl",
        "-severity", NUCLEI_SEVERITY,
        "-rate-limit", str(DEFAULT_RATE_LIMIT),
    ]
    # nuclei runs its full template set per URL -- against more than a
    # handful of URLs this routinely takes longer than the generic 900s
    # tool timeout (observed: silently killed mid-scan, returning 0
    # findings that looked like "clean target" but were actually "timed
    # out"). Give it real headroom.
    out, err, rc = await _run(cmd, stdin_data="\n".join(urls), timeout=1800)
    raw_path(target_label, "nuclei.jsonl").write_text(out)
    timed_out = rc == -1 and "timed out" in err
    if timed_out:
        log.warning("nuclei: timed out against %d urls -- results are incomplete, not necessarily clean", len(urls))
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    log.info("nuclei: %d findings%s", len(findings), " (timed out, incomplete)" if timed_out else "")
    return findings, timed_out


async def run_gobuster(live_urls: list[str], target_label: str) -> list[str]:
    """Directory/file brute-force against a capped number of live hosts.
    Runs against the target's own URL only (no link-following), so unlike
    katana there's no scope-leak risk here."""
    discovered: list[str] = []
    all_out = []
    for url in live_urls[:GOBUSTER_MAX_HOSTS]:
        cmd = [
            TOOL_PATHS["gobuster"], "dir", "-u", url,
            "-w", GOBUSTER_WORDLIST,
            "-t", str(GOBUSTER_THREADS),
            "-q", "--no-error",
        ]
        out, err, rc = await _run(cmd, timeout=300)
        all_out.append(f"### {url}\n{out}")
        for line in out.splitlines():
            line = line.strip()
            if not line or "(Status:" not in line:
                continue
            path = line.split()[0].strip()
            discovered.append(url.rstrip("/") + "/" + path.lstrip("/"))
    raw_path(target_label, "gobuster.txt").write_text("\n\n".join(all_out))
    log.info("gobuster: %d paths discovered across %d hosts", len(discovered), min(len(live_urls), GOBUSTER_MAX_HOSTS))
    return discovered


async def run_katana(urls: list[str], target_label: str, scope: Scope) -> list[str]:
    if not urls:
        return []
    cmd = [
        TOOL_PATHS["katana"], "-silent", "-jc",
        "-field-scope", "rdn",  # stay on the root domain of each seed URL, never follow off-site links
        "-depth", str(KATANA_MAX_DEPTH),
        "-concurrency", str(KATANA_CONCURRENCY),
        "-rate-limit", str(DEFAULT_RATE_LIMIT),
    ]
    out, err, rc = await _run(cmd, stdin_data="\n".join(urls))
    raw_path(target_label, "katana.txt").write_text(out)

    crawled = [l.strip() for l in out.splitlines() if l.strip()]
    # Defense in depth: katana's own domain scoping shouldn't let anything
    # off-target through, but explicit scope excludes (e.g. !staging.foo.com)
    # are only enforced here, and a hard cap protects against crawl blowup
    # even on in-scope hosts (huge sites, infinite-pagination traps, etc).
    in_scope = [u for u in crawled if scope.is_in_scope(urlparse(u).netloc)]
    capped = in_scope[:MAX_CRAWL_URLS]
    if len(crawled) != len(capped):
        log.warning(
            "katana: %d raw urls -> %d in-scope -> capped to %d",
            len(crawled), len(in_scope), len(capped),
        )
    else:
        log.info("katana: %d crawled urls", len(capped))
    return capped


async def run_naabu(host: str, target_label: str) -> list[int]:
    cmd = [TOOL_PATHS["naabu"], "-host", host, "-silent", "-json", "-top-ports", "1000", "-rate", "1000"]
    out, err, rc = await _run(cmd, timeout=300)
    raw_path(target_label, "naabu.jsonl").write_text(out)
    ports = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            if "port" in d:
                ports.append(int(d["port"]))
        except (json.JSONDecodeError, ValueError):
            continue
    ports = sorted(set(ports))
    log.info("naabu: %d open ports on %s", len(ports), host)
    return ports


async def run_nmap(host: str, ports: list[int], target_label: str) -> str:
    if not ports:
        return ""
    port_str = ",".join(str(p) for p in ports)
    cmd = [TOOL_PATHS["nmap"], "-sV", "-Pn", "-p", port_str, host]
    out, err, rc = await _run(cmd, timeout=300)
    raw_path(target_label, "nmap.txt").write_text(out)
    return out


async def run_dalfox(urls_with_params: list[str], target_label: str) -> list[dict]:
    candidates = [u for u in urls_with_params if "?" in u][:MAX_DALFOX_URLS]
    if not candidates:
        return []
    cmd = [TOOL_PATHS["dalfox"], "pipe", "--silence", "--format", "json"]
    out, err, rc = await _run(cmd, stdin_data="\n".join(candidates))
    raw_path(target_label, "dalfox.json").write_text(out)
    try:
        raw = json.loads(out) if out.strip() else []
    except json.JSONDecodeError:
        raw = []
    # dalfox's pipe+json output mixes real PoC objects with empty `{}`
    # placeholders for URLs where nothing was found -- only keep entries
    # that actually carry a PoC (see model.PoC in dalfox's source: the
    # populated fields are "data" [the triggering URL], "param", "payload").
    findings = [d for d in raw if isinstance(d, dict) and d.get("data")]
    log.info("dalfox: %d real findings (of %d raw entries)", len(findings), len(raw) if isinstance(raw, list) else 0)
    return findings


async def _store_finding(job_id: int, target_label: str, tool: str, kind: str,
                          severity: str, title: str, matched_url: str, evidence: dict) -> int:
    """Persist a finding, run AI triage, and capture a PoC screenshot."""
    fid = db.add_finding(
        job_id=job_id, target=target_label, tool=tool, kind=kind, severity=severity,
        title=title, matched_url=matched_url, evidence=json.dumps(evidence)[:4000],
    )
    triage = triage_finding({
        "tool": tool, "kind": kind, "severity": severity, "title": title,
        "matched_url": matched_url, "evidence": json.dumps(evidence)[:2000],
    })
    db.set_triage_fields(
        fid, description=triage["description"], risk=triage["risk"], reasoning=triage["reasoning"],
        manual_steps=triage["manual_verification_steps"], remediation=triage["remediation"],
        ai_summary=triage["ai_summary"], ai_confidence=triage["ai_confidence"],
    )

    if matched_url:
        shot_path = target_dir(target_label) / "screenshots" / f"finding_{fid}.png"
        if await capture_screenshot(matched_url, shot_path):
            db.set_screenshot(fid, str(shot_path))

    return fid


async def run_subdomain_enum(root_domain: str, scope_text: str = "") -> str:
    """Standalone: subfinder + httpx only. No vuln scanning, no AI, fast."""
    target_label = root_domain
    target_dir(target_label)
    scope = Scope.parse(scope_text) if scope_text.strip() else Scope(includes=[root_domain], excludes=[])

    subs = await run_subfinder(root_domain, target_label)
    subs.append(root_domain)
    subs = scope.filter(list(dict.fromkeys(subs)))
    live = await run_httpx(subs, target_label)

    lines = [f"Subdomain enum for {root_domain}: {len(subs)} in-scope, {len(live)} live.\n"]
    for h in live[:40]:
        lines.append(f"- {h.get('url')} [{h.get('status_code')}] {h.get('title', '')} ({h.get('webserver', '')})")
    if len(live) > 40:
        lines.append(f"... and {len(live) - 40} more (see data/targets/{target_label}/httpx.jsonl)")
    return "\n".join(lines)


async def run_port_scan_standalone(host: str, scope_text: str = "") -> str:
    """Standalone: naabu (fast port discovery) + nmap (service/version detection)."""
    target_label = host
    target_dir(target_label)
    scope = Scope.parse(scope_text) if scope_text.strip() else Scope(includes=[host], excludes=[])
    if not scope.is_in_scope(host):
        return f"{host} is not in the scope you provided -- refusing to scan."

    ports = await run_naabu(host, target_label)
    if not ports:
        return f"Port scan for {host}: no open ports found in top 1000."

    nmap_out = await run_nmap(host, ports, target_label)
    lines = [f"Port scan for {host}: {len(ports)} open ports: {', '.join(str(p) for p in ports)}\n"]
    lines.append("nmap service detection:")
    lines.append(nmap_out[-2500:] if len(nmap_out) > 2500 else nmap_out)
    return "\n".join(lines)


async def run_web_vuln_scan(url: str) -> str:
    """Standalone: nuclei against a single URL, with AI triage per finding."""
    target_label = urlparse(url).netloc or url
    target_dir(target_label)

    findings, timed_out = await run_nuclei([url], target_label)
    if not findings:
        note = " (scan timed out -- incomplete, not necessarily clean)" if timed_out else ""
        return f"nuclei scan of {url}: no findings{note}."

    lines = [f"nuclei scan of {url}: {len(findings)} findings.\n"]
    for f in findings[:15]:
        info = f.get("info", {})
        triage = triage_finding({
            "tool": "nuclei", "kind": f.get("template-id", "unknown"),
            "severity": info.get("severity", "info"), "title": info.get("name", ""),
            "matched_url": f.get("matched-at", ""), "evidence": json.dumps(f)[:2000],
        })
        lines.append(f"[{info.get('severity', 'info').upper()}] {info.get('name', f.get('template-id'))}")
        lines.append(f"  {triage['ai_summary'][:400]}")
    if len(findings) > 15:
        lines.append(f"... and {len(findings) - 15} more (see data/targets/{target_label}/nuclei.jsonl)")
    return "\n".join(lines)


async def run_dir_scan_standalone(url: str) -> str:
    """Standalone: gobuster directory brute-force against a single URL."""
    target_label = urlparse(url).netloc or url
    target_dir(target_label)
    paths = await run_gobuster([url], target_label)
    if not paths:
        return f"gobuster scan of {url}: no paths found."
    lines = [f"gobuster scan of {url}: {len(paths)} paths found.\n"]
    lines.extend(f"- {p}" for p in paths[:40])
    return "\n".join(lines)


async def run_pipeline(job_id: int, root_domain: str, scope_text: str = "") -> dict:
    target_label = root_domain
    target_dir(target_label)  # ensure folder exists
    # No scope text provided -> default to "just this domain and its
    # subdomains", never wide-open. Wide-open is what let katana wander
    # onto github.com/twitter.com/etc in testing.
    if scope_text.strip():
        scope = Scope.parse(scope_text)
    else:
        scope = Scope(includes=[root_domain], excludes=[])

    db.update_job_status(job_id, "running")
    try:
        db.set_phase(job_id, "subfinder")
        subs = await run_subfinder(root_domain, target_label)
        subs.append(root_domain)
        subs = scope.filter(list(dict.fromkeys(subs)))

        db.set_phase(job_id, "httpx")
        live = await run_httpx(subs, target_label)
        live_urls = [h["url"] for h in live if "url" in h]

        db.set_phase(job_id, "katana")
        crawled = await run_katana(live_urls, target_label, scope)
        db.set_phase(job_id, "gobuster")
        gobuster_paths = await run_gobuster(live_urls, target_label)

        # scan both the crawled surface and anything gobuster dug up that
        # crawling wouldn't have linked to (backup files, hidden admin
        # panels, etc.)
        db.set_phase(job_id, "nuclei_scan")
        nuclei_targets = list(dict.fromkeys(live_urls + gobuster_paths))
        nuclei_findings, nuclei_timed_out = await run_nuclei(nuclei_targets, target_label)
        db.set_phase(job_id, "dalfox_scan")
        dalfox_findings = await run_dalfox(crawled, target_label)

        total_to_triage = len(nuclei_findings) + len(dalfox_findings)
        db.set_phase(job_id, "triaging", 0, total_to_triage)
        stored = 0
        for f in nuclei_findings:
            info = f.get("info", {})
            await _store_finding(
                job_id, target_label, tool="nuclei",
                kind=f.get("template-id", "unknown"),
                severity=info.get("severity", "info"),
                title=info.get("name", f.get("template-id", "finding")),
                matched_url=f.get("matched-at", f.get("host", "")),
                evidence=f,
            )
            stored += 1
            db.set_phase(job_id, "triaging", stored, total_to_triage)

        for f in dalfox_findings:
            await _store_finding(
                job_id, target_label, tool="dalfox", kind="reflected-xss",
                severity=(f.get("severity") or "medium").lower(),
                title=f.get("message_str") or f"Reflected XSS via param '{f.get('param', '?')}'",
                matched_url=f.get("data", ""),
                evidence=f,
            )
            stored += 1
            db.set_phase(job_id, "triaging", stored, total_to_triage)

        nuclei_note = " (TIMED OUT -- incomplete, not a clean result)" if nuclei_timed_out else ""
        summary = (
            f"{len(subs)} in-scope hosts, {len(live)} live, "
            f"{len(gobuster_paths)} gobuster paths, "
            f"{len(nuclei_findings)} nuclei hits{nuclei_note}, {len(dalfox_findings)} dalfox hits, "
            f"{stored} findings stored."
        )

        # Phase 2: one aggregate pass over everything found, looking for
        # chains/patterns that per-finding triage can't see.
        db.set_phase(job_id, "aggregate_analysis")
        all_findings = db.list_findings(job_id=job_id, limit=1000)
        risk_text = aggregate_analysis(target_label, [dict(f) for f in all_findings])
        db.set_risk_analysis(job_id, risk_text)

        # Manual testing suggestions from the recon surface itself, grounded
        # in the reference writeup corpus -- most valuable exactly when
        # automated scanners found little or nothing (common against a
        # deliberately-built app rather than a misconfigured real target).
        db.set_phase(job_id, "recon_suggestions")
        recon_urls = list(dict.fromkeys(live_urls + crawled + gobuster_paths))
        recon_text = recon_suggestions(target_label, recon_urls)
        db.set_recon_suggestions(job_id, recon_text)

        db.set_phase(job_id, "done")
        db.update_job_status(job_id, "done", summary)
        return {"ok": True, "summary": summary}
    except asyncio.CancelledError:
        log.info("job %s cancelled", job_id)
        db.set_phase(job_id, "cancelled")
        db.update_job_status(job_id, "cancelled", "Cancelled by operator.")
        raise
    except Exception as e:
        log.exception("pipeline failed")
        db.set_phase(job_id, "failed")
        db.update_job_status(job_id, "failed", str(e))
        return {"ok": False, "summary": str(e)}
