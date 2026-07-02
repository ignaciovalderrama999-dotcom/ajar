"""Project configuration loaded from a transparent ``.ajar.yml`` file.

The config lets a project set its defaults once instead of repeating flags:

    # .ajar.yml
    min_severity: low
    fail_on: high
    exclude:
      - tests
      - "*.min.js"
    disable:
      - DEFAULT_BIND_ALL_INTERFACES

Explicit command-line flags always win over the config file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

CONFIG_NAMES = (".ajar.yml", ".ajar.yaml")


class ConfigError(ValueError):
    """Raised when a config file is malformed."""


@dataclass
class Config:
    min_severity: str | None = None
    fail_on: str | None = None
    exclude: tuple[str, ...] = ()
    disable: frozenset[str] = field(default_factory=frozenset)


def find_config(start: Path) -> Path | None:
    """Look for a config file in ``start`` (or its parent if start is a file)."""

    base = start if start.is_dir() else start.parent
    for name in CONFIG_NAMES:
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path) -> Config:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path.name}: top level must be a mapping")

    def _as_list(key: str) -> tuple[str, ...]:
        value = data.get(key, []) or []
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            raise ConfigError(f"{path.name}: '{key}' must be a list")
        return tuple(str(v) for v in value)

    return Config(
        min_severity=str(data["min_severity"]).lower() if data.get("min_severity") else None,
        fail_on=str(data["fail_on"]).lower() if data.get("fail_on") else None,
        exclude=_as_list("exclude"),
        disable=frozenset(_as_list("disable")),
    )
