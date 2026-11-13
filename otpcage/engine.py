"""TOTP verification with a replay ledger. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any

from otpcage.account import Account
from otpcage.policy import Policy


def verify_totp(
    account: Account,
    code: str,
    ledger: list[dict[str, Any]],
    policy: Policy,
    *,
    now: int,
) -> dict[str, Any]:
    """Return a report. On allow, include used_timestep so the CLI can append the ledger."""
    raise NotImplementedError("verify_totp is not implemented in this snapshot")
