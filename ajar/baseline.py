"""Baseline files: accept today's findings, flag only new ones from then on."""

from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from .models import Finding

DEFAULT_BASELINE = ".ajar-baseline.json"


class BaselineError(ValueError):
    """Raised when a baseline file can't be read."""


def load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BaselineError(f"could not read baseline {path}: {exc}") from exc
    return set(data.get("fingerprints", []))


def write_baseline(path: Path, findings: list[Finding]) -> None:
    payload = {
        "tool": "ajar",
        "version": __version__,
        "fingerprints": sorted({f.fingerprint() for f in findings}),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
