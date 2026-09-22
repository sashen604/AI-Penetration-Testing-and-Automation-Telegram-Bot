"""Ingests vulnerability writeup repos into the reference_knowledge table.

This is the other half of the "training" story: alongside the operator
feedback loop (lessons table), this gives the AI a curated corpus of real
technique writeups to draw on during triage and aggregate analysis --
concrete PoC patterns for vulnerability classes that generic scanner
templates (nuclei) don't cover, like business logic and access control.
"""
import re
import sys
from pathlib import Path

from orchestrator import db

MAX_CONTENT_CHARS = 3000
_IMAGE_LINE_RE = re.compile(r"^!\[.*?\]\(.*?\)\s*$", re.MULTILINE)


def _clean_markdown(text: str) -> str:
    # strip image embeds (screenshots) -- not renderable as text, just noise
    text = _IMAGE_LINE_RE.sub("", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def ingest_repo(repo_dir: str, source_url: str) -> int:
    root = Path(repo_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"{repo_dir} is not a directory")

    db.init_db()
    db.clear_references(source_url)

    count = 0
    for category_dir in sorted(root.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("."):
            continue
        category = category_dir.name

        for md_file in sorted(category_dir.rglob("*.md")):
            raw = md_file.read_text(errors="replace")
            cleaned = _clean_markdown(raw)
            if len(cleaned) < 50:
                continue  # skip empty/near-empty files, not worth storing
            cleaned = cleaned[:MAX_CONTENT_CHARS]

            rel = md_file.relative_to(root)
            # title: the lab subfolder name if there is one, else the filename
            title = rel.parent.name if rel.parent != Path(".") and rel.parent.name != category else md_file.stem
            if title == category:
                title = md_file.stem

            db.add_reference(
                category=category, title=title, content=cleaned,
                source=source_url,
            )
            count += 1

    return count


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python -m orchestrator.knowledge_ingest <repo_dir> <source_url>")
        sys.exit(1)
    n = ingest_repo(sys.argv[1], sys.argv[2])
    print(f"Ingested {n} writeups from {sys.argv[1]}")
    for cat, cnt in db.reference_category_counts():
        print(f"  {cat}: {cnt}")
