"""CLI. inspect already works; verify is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from otpcage.account import AccountError, LedgerError, account_to_dict, load_account, load_ledger
from otpcage.policy import PolicyError, load_policy


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="otpcage")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="print an account record without verifying a code")
    ins.add_argument("--account", required=True)
    ver = sub.add_parser("verify", help="fail-closed TOTP verification against a replay ledger")
    ver.add_argument("--account", required=True)
    ver.add_argument("--code", required=True, help="the digit string offered by the user")
    ver.add_argument("--ledger", required=True, help="JSON ledger of used account_id/timestep pairs")
    ver.add_argument("--policy", required=True)
    ver.add_argument("--report", required=True)
    ver.add_argument("--now", type=int, default=None, help="unix timestamp used to compute the timestep")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        account = load_account(args.account)
    except (AccountError, OSError) as exc:
        print(f"failed to read account: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "inspect":
        print(json.dumps(account_to_dict(account), ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "verify":
        try:
            policy = load_policy(args.policy)
            ledger = load_ledger(args.ledger)
        except (PolicyError, LedgerError, OSError) as exc:
            print(f"failed to load policy or ledger: {exc}", file=sys.stderr)
            return 2
        now = args.now if args.now is not None else int(time.time())
        from otpcage.engine import verify_totp
        try:
            report = verify_totp(account, args.code, ledger, policy, now=now)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"verify failed unexpectedly: {exc}", file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            # Persist the consumed timestep so a second verify in the same window fails.
            used_ts = report.get("used_timestep")
            if isinstance(used_ts, int) and not isinstance(used_ts, bool):
                data = json.loads(Path(args.ledger).read_text(encoding="utf-8"))
                data.setdefault("used", []).append({"account_id": account.account_id, "timestep": used_ts})
                Path(args.ledger).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
