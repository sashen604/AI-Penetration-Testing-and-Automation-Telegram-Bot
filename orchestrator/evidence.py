"""PoC screenshot capture for findings.

Uses plain headless chromium directly rather than gowitness's chromedp
driver -- on this machine gowitness hangs because the system chromium
wrapper injects Wayland/extension flags that conflict with chromedp's
persistent CDP session. One-shot `--screenshot=` mode sidesteps that.
"""
import asyncio
import logging

log = logging.getLogger("evidence")

CHROMIUM_PATH = "/usr/bin/chromium"


async def capture_screenshot(url: str, out_path, timeout: int = 25) -> bool:
    """Renders `url` and writes a PNG to out_path. Returns True on success."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        CHROMIUM_PATH, "--headless", "--no-sandbox", "--disable-gpu",
        "--disable-dev-shm-usage", "--window-size=1280,1024",
        "--virtual-time-budget=8000", "--hide-scrollbars",
        f"--screenshot={out_path}", url,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        log.warning("screenshot timed out for %s", url)
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return False

    ok = out_path.exists() and out_path.stat().st_size > 0
    if not ok:
        log.warning("screenshot failed for %s", url)
    return ok
