"""Per-target evidence folders."""
import re
from pathlib import Path

from orchestrator.config import TARGETS_DIR


def safe_name(target: str) -> str:
    return re.sub(r"[^a-zA-Z0-9.-]", "_", target.strip().lower())


def target_dir(target: str) -> Path:
    d = TARGETS_DIR / safe_name(target)
    d.mkdir(parents=True, exist_ok=True)
    return d


def raw_path(target: str, filename: str) -> Path:
    return target_dir(target) / filename
