"""TOTP verification policy loader."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    period_seconds: int
    digits: int
    window: int
    raw: dict[str, Any] = field(default_factory=dict)


def load_policy(path: str | Path) -> Policy:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyError(f"failed to read policy: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object")

    def _int(name: str, default: int, minimum: int = 0) -> int:
        val = data.get(name, default)
        if not isinstance(val, int) or isinstance(val, bool) or val < minimum:
            raise PolicyError(f"{name} must be an integer >= {minimum}")
        return val

    digits = _int("digits", 6, 1)
    if digits not in (6, 7, 8):
        raise PolicyError("digits must be 6, 7, or 8")
    return Policy(
        period_seconds=_int("period_seconds", 30, 1),
        digits=digits,
        window=_int("window", 1, 0),
        raw=data,
    )
