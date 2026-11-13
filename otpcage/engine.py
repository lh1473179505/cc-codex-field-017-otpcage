"""Fail-closed TOTP (RFC 6238, HMAC-SHA1) verification with a replay ledger."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
from typing import Any

from otpcage.account import Account
from otpcage.policy import Policy


def _decode_secret(secret_base32: str) -> bytes | None:
    """Decode an RFC 4648 Base32 secret; padding '=' is optional.

    Returns None when decoding fails or the decoded secret is empty so the
    caller can fail closed instead of raising.
    """
    if not isinstance(secret_base32, str) or secret_base32 == "":
        return None
    padded = secret_base32 + ("=" * ((-len(secret_base32)) % 8))
    try:
        decoded = base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError):
        return None
    return decoded or None


def _hotp(secret: bytes, counter: int, digits: int) -> str:
    """HOTP per RFC 4226, returned as a zero-padded decimal string."""
    message = struct.pack(">Q", counter)
    digest = hmac.new(secret, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def _deny(account_id: str, reason_codes: list[str]) -> dict[str, Any]:
    return {
        "decision": "deny",
        "reason_codes": reason_codes,
        "account_id": account_id,
        "used_timestep": None,
    }


def verify_totp(
    account: Account,
    code: str,
    ledger: list[dict[str, Any]],
    policy: Policy,
    *,
    now: int,
) -> dict[str, Any]:
    """Return a report. On allow, include used_timestep so the CLI can append the ledger."""
    reason_codes: list[str] = []
    digits = policy.digits

    code_valid = (
        isinstance(code, str)
        and len(code) == digits
        and all("0" <= char <= "9" for char in code)
    )
    if not code_valid:
        reason_codes.append("bad_code")

    secret = _decode_secret(account.secret_base32)
    if secret is None:
        reason_codes.append("bad_secret")

    if reason_codes:
        return _deny(account.account_id, reason_codes)

    t0 = now // policy.period_seconds
    offered = code.zfill(digits)
    matching_steps: list[int] = []
    for timestep in range(t0 - policy.window, t0 + policy.window + 1):
        expected = _hotp(secret, timestep, digits)
        if hmac.compare_digest(offered, expected):
            matching_steps.append(timestep)

    if not matching_steps:
        return _deny(account.account_id, ["bad_code"])

    # Closest to t0; on a tie prefer the smaller timestep.
    used_timestep = min(matching_steps, key=lambda step: (abs(step - t0), step))

    if any(
        entry.get("account_id") == account.account_id and entry.get("timestep") == used_timestep
        for entry in ledger
    ):
        return _deny(account.account_id, ["replay"])

    return {
        "decision": "allow",
        "reason_codes": [],
        "account_id": account.account_id,
        "used_timestep": used_timestep,
    }
