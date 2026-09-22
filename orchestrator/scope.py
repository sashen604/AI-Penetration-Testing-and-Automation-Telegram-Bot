"""Scope parsing and enforcement.

Scope files are plain text, one rule per line:
  *.example.com          -> in scope (wildcard)
  example.com            -> in scope (exact/subdomains)
  !shop.example.com      -> explicitly OUT of scope (takes priority)
  # comment lines and blank lines are ignored
"""
import fnmatch
from dataclasses import dataclass


@dataclass
class Scope:
    includes: list[str]
    excludes: list[str]

    @classmethod
    def parse(cls, text: str) -> "Scope":
        includes, excludes = [], []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):
                excludes.append(line[1:].strip())
            else:
                includes.append(line)
        return cls(includes=includes, excludes=excludes)

    def is_in_scope(self, host: str) -> bool:
        host = host.strip().lower()
        for pat in self.excludes:
            if _matches(host, pat):
                return False
        if not self.includes:
            return True
        return any(_matches(host, pat) for pat in self.includes)

    def filter(self, hosts: list[str]) -> list[str]:
        return [h for h in hosts if self.is_in_scope(h)]


def _matches(host: str, pattern: str) -> bool:
    pattern = pattern.lower().strip()
    if not pattern.startswith("*"):
        # bare domain also covers subdomains
        if host == pattern or host.endswith("." + pattern):
            return True
    return fnmatch.fnmatch(host, pattern)
