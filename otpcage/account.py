"""Account and replay-ledger loaders."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class AccountError(ValueError):
    pass


class LedgerError(ValueError):
    pass


@dataclass
class Account:
    account_id: str
    secret_base32: str
    raw: dict[str, Any] = field(default_factory=dict)


def load_account(path: str | Path) -> Account:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise AccountError(f"failed to read account: {exc}") from exc
    if not isinstance(data, dict):
        raise AccountError("account must be a JSON object")
    account_id = data.get("account_id")
    secret = data.get("secret_base32")
    if not isinstance(account_id, str) or account_id == "":
        raise AccountError("account_id must be a non-empty string")
    if not isinstance(secret, str) or secret == "":
        raise AccountError("secret_base32 must be a non-empty string")
    return Account(account_id=account_id, secret_base32=secret, raw=data)


def load_ledger(path: str | Path) -> list[dict[str, Any]]:
    """Return the list of used (account_id, timestep) records. Missing file is an error."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise LedgerError(f"failed to read ledger: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("used"), list):
        raise LedgerError("ledger must be an object with a used array")
    for item in data["used"]:
        if not isinstance(item, dict):
            raise LedgerError("ledger entry must be an object")
        if not isinstance(item.get("account_id"), str) or not isinstance(item.get("timestep"), int) or isinstance(item.get("timestep"), bool):
            raise LedgerError("ledger entry needs account_id (string) and timestep (int)")
    return list(data["used"])


def account_to_dict(account: Account) -> dict[str, Any]:
    return {
        "account_id": account.account_id,
        "secret_base32": account.secret_base32,
        "secret_length": len(account.secret_base32),
    }
