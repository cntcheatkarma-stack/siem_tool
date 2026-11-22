"""Log parsers. Each one turns raw log text into normalized `Event` objects."""

from __future__ import annotations

from pathlib import Path

from ..models import Event
from .linux_auth import parse_linux_auth
from .windows import parse_windows

PARSERS = {
    "linux_auth": parse_linux_auth,
    "windows": parse_windows,
}


def detect_format(path: Path, text: str) -> str:
    """Guess the log format from the file name, then the content."""
    if path.suffix.lower() in (".json", ".jsonl", ".ndjson"):
        return "windows"
    if text.lstrip().startswith(("{", "[")):
        return "windows"
    return "linux_auth"


def parse_file(path: Path, fmt: str | None = None, year: int | None = None) -> tuple[list[Event], int]:
    """Parse one file. Returns (events, number_of_lines_or_records_skipped)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    fmt = fmt or detect_format(path, text)
    if fmt not in PARSERS:
        raise ValueError(f"unknown format '{fmt}' (choose from {', '.join(PARSERS)})")
    if fmt == "linux_auth":
        return parse_linux_auth(text, year=year)
    return parse_windows(text)
