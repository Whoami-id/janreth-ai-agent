"""Voice gate - fail the build on the hype lexicon or leftover book markers.

Scans the Janreth-authored surface (the security layer, attacks, examples, scripts,
and the README). Keeps the code reading like Janreth: evidence-first, plain, no
vendor theatre.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN_DIRS = ["janreth/security", "attacks", "examples", "scripts"]
SCAN_FILES = ["README.md"]

# Hype / vendor-theatre lexicon (case-insensitive, whole-word where sensible).
BANNED = [
    "robust", "seamless", "military-grade", "blazing", "effortless",
    "cutting-edge", "next-gen", "world-class", "revolutionary",
    "game-chang", "synergy", "unparalleled", "100% safe", "zero risk", "bulletproof",
]
_BANNED_RES = [(w, re.compile(r"(?i)" + re.escape(w))) for w in BANNED]
_AI_POWERED = re.compile(r"(?i)\bAI[- ]powered\b")
_MARKER = re.compile(r"\bCH\d+\b|\bListing \d+\.\d+")


def _iter_paths():
    for directory in SCAN_DIRS:
        for path in sorted((ROOT / directory).rglob("*.py")):
            if path.name == "check_voice.py":
                continue  # this file legitimately contains the banned lexicon
            yield path
    for name in SCAN_FILES:
        path = ROOT / name
        if path.exists():
            yield path


def main() -> int:
    failures: list[str] = []
    for path in _iter_paths():
        rel = path.relative_to(ROOT)
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for word, rx in _BANNED_RES:
                if rx.search(line):
                    failures.append(f"{rel}:{lineno}: hype lexicon ({word!r}): {line.strip()[:80]}")
            if _AI_POWERED.search(line):
                failures.append(f"{rel}:{lineno}: 'AI-powered': {line.strip()[:80]}")
            if _MARKER.search(line):
                failures.append(f"{rel}:{lineno}: leftover book marker: {line.strip()[:80]}")

    if failures:
        print("voice check FAILED:")
        for failure in failures:
            print("  " + failure)
        return 1
    print("voice check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
