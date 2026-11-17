from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def clean(s: str | None, n: int) -> str:
    """Printable-only + truncated, so attacker input can never forge log lines or bloat storage."""
    return "".join(ch if ch.isprintable() else "?" for ch in (s or "")[:n])


def trim_log(s: str, limit: int = 8000) -> str:
    if len(s) <= limit:
        return s
    s = s[-limit:]
    return "…[older entries truncated]\n" + s[s.find("\n") + 1:]
