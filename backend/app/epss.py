from __future__ import annotations

import csv
import os
from dataclasses import dataclass

from .config import settings


@dataclass(slots=True)
class EpssCache:
    path: str
    mtime: float = 0.0
    scores: dict[str, float] | None = None


_CACHE = EpssCache(path=settings.epss_csv_path, scores={})


def _safe_float(value: str | None) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _load_scores(path: str) -> dict[str, float]:
    if not os.path.exists(path):
        return {}

    scores: dict[str, float] = {}
    with open(path, "r", encoding="utf-8", newline="") as handle:
        lines = handle.readlines()

    # EPSS feeds often start with a metadata comment line.
    if lines and lines[0].startswith("#"):
        lines = lines[1:]
    if not lines:
        return {}

    reader = csv.DictReader(lines)
    for row in reader:
        cve = (row.get("cve") or row.get("CVE") or "").strip().upper()
        if not cve:
            continue
        score = _safe_float(row.get("epss") or row.get("score"))
        scores[cve] = score
    return scores


def refresh_epss_cache() -> dict[str, int | str]:
    path = settings.epss_csv_path
    _CACHE.path = path
    _CACHE.mtime = os.path.getmtime(path) if os.path.exists(path) else 0.0
    _CACHE.scores = _load_scores(path)
    return {"path": path, "entries": len(_CACHE.scores or {})}


def _ensure_cache() -> None:
    path = settings.epss_csv_path
    mtime = os.path.getmtime(path) if os.path.exists(path) else 0.0
    if _CACHE.scores is None or _CACHE.path != path or _CACHE.mtime != mtime:
        refresh_epss_cache()


def get_epss_score(cve: str | None) -> float | None:
    if not cve:
        return None
    _ensure_cache()
    return (_CACHE.scores or {}).get(cve.strip().upper())


def epss_status() -> dict[str, int | str]:
    _ensure_cache()
    return {"path": _CACHE.path, "entries": len(_CACHE.scores or {}), "mtime": int(_CACHE.mtime)}
