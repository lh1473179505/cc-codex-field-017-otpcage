# otpcage

A small fail-closed TOTP checker with a replay ledger. Account and ledger loading already work. `inspect` prints an account id and the Base32 secret, and `verify` checks a TOTP code against the configured window while rejecting replayed `(account_id, timestep)` pairs.

The current second-factor path only compared the current 30-second window and would accept the same digits twice. This tool must reject a reused `(account_id, timestep)` pair and still accept a code from the adjacent step inside the configured window.

## Requirements

- Python 3.11+
- Standard library only (`hmac`, `hashlib`)
- No containers, no TOTP package

## Already working

```bash
python -m otpcage inspect --account fixtures/accounts/alice.json
```

Public codes are computed around Unix time `1763000000`. Alice's current code at that instant is `536499`.

## Intended CLI

```bash
python -m otpcage verify \
  --account fixtures/accounts/alice.json \
  --code 536499 \
  --ledger /tmp/otpcage-ledger.json \
  --policy fixtures/policy.json \
  --report /tmp/otpcage-report.json \
  --now 1763000000
```

Copy `fixtures/ledgers/empty.json` to the `--ledger` path before a successful allow, because the CLI appends the consumed timestep on exit 0. Parameter names are fixed in `otpcage/__main__.py`. Keep them.
