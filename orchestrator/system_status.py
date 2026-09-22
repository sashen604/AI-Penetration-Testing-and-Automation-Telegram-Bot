"""System, AI model, and scan-process monitoring for the dashboard."""
import logging

import ollama
import psutil

from orchestrator.config import OLLAMA_HEALTHCHECK_TIMEOUT, OLLAMA_HOST, OLLAMA_MODEL

log = logging.getLogger("system_status")

# Binary names the pipeline shells out to -- matched against running
# processes so the dashboard can show live scan activity, not just DB status.
SCAN_TOOL_NAMES = {
    "subfinder", "httpx", "katana", "gobuster", "nuclei", "dalfox",
    "naabu", "nmap", "chromium", "ollama",
}

# psutil.Process.cpu_percent() needs to be called twice on the SAME object,
# with a gap, to report a real number -- a fresh Process() always reports
# 0.0 on its first call. Since this module gets polled repeatedly by the
# dashboard, caching Process objects across polls gives an accurate
# "CPU% since last poll" instead of always showing 0.
_process_cache: dict[int, psutil.Process] = {}


def _cached_process(pid: int) -> psutil.Process:
    proc = _process_cache.get(pid)
    if proc is None or not proc.is_running():
        proc = psutil.Process(pid)
        proc.cpu_percent(interval=None)  # prime it; first call is always 0.0
        _process_cache[pid] = proc
    return proc


def get_system_stats() -> dict:
    vm = psutil.virtual_memory()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "mem_percent": vm.percent,
        "mem_used_gb": round(vm.used / 1e9, 1),
        "mem_total_gb": round(vm.total / 1e9, 1),
    }


def get_ollama_process_stats() -> dict:
    """Sums RSS/CPU across the ollama server AND its llama-server runner
    child (that's where the model weights actually live in memory -- the
    'ollama serve' process itself stays small)."""
    total_rss = 0
    total_cpu = 0.0
    pids = []
    for proc in psutil.process_iter(["name", "pid"]):
        try:
            name = (proc.info["name"] or "").lower()
            if "ollama" in name or "llama-server" in name or "llama_server" in name:
                cached = _cached_process(proc.info["pid"])
                total_rss += cached.memory_info().rss
                total_cpu += cached.cpu_percent(interval=None)
                pids.append(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {"running": bool(pids), "pids": pids, "mem_gb": round(total_rss / 1e9, 2), "cpu_percent": round(total_cpu, 1)}


def get_ollama_model_status() -> dict:
    try:
        client = ollama.Client(host=OLLAMA_HOST, timeout=OLLAMA_HEALTHCHECK_TIMEOUT)
        loaded = client.ps()
        models = []
        for m in loaded.models:
            models.append({
                "name": m.model,
                "size_gb": round(m.size / 1e9, 2),
                "using_gpu": bool(m.size_vram and m.size_vram > 0),
                "expires_at": m.expires_at.strftime("%H:%M:%S") if m.expires_at else None,
            })
        return {"online": True, "target_model": OLLAMA_MODEL, "loaded_models": models, "error": None}
    except Exception as e:
        return {"online": False, "target_model": OLLAMA_MODEL, "loaded_models": [], "error": str(e)}


def get_running_scan_processes() -> list[dict]:
    procs = []
    for proc in psutil.process_iter(["name", "pid", "cmdline"]):
        try:
            name = proc.info["name"] or ""
            if name.lower() not in SCAN_TOOL_NAMES:
                continue
            if name.lower() == "chromium" and "--headless" not in " ".join(proc.info["cmdline"] or []):
                continue  # ignore the user's own desktop browser, only screenshot workers matter
            if name.lower() == "ollama":
                continue  # shown separately in get_ollama_process_stats
            cached = _cached_process(proc.info["pid"])
            procs.append({
                "name": name,
                "pid": proc.info["pid"],
                "mem_mb": round(cached.memory_info().rss / 1e6, 1),
                "cpu_percent": round(cached.cpu_percent(interval=None), 1),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, IndexError):
            continue
    return procs


def get_full_status() -> dict:
    return {
        "system": get_system_stats(),
        "ollama_process": get_ollama_process_stats(),
        "ollama_model": get_ollama_model_status(),
        "scan_processes": get_running_scan_processes(),
    }
