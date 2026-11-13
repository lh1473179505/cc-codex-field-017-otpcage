# Verify rules

`verify` is fail-closed TOTP (RFC 6238, HMAC-SHA1) with a persistent replay ledger. An unreadable account, policy, or ledger file is a process error (exit 2). A request that can be read must produce an allow or deny report.

Reuse `load_account`, `load_ledger`, and `load_policy`. Do not add a TOTP library. Compare the offered code using `hmac.compare_digest` on equal-length strings (zero-pad numeric codes to `policy.digits`).

`--now` is the Unix timestamp used to compute the current timestep `floor(now / period_seconds)`. When it is omitted, the current time is used. Public fixtures are computed around `1763000000`.

The CLI already appends `{"account_id", "used_timestep"}` to `--ledger` when the report is `allow` and `used_timestep` is an integer. The engine must put the consumed timestep in that field on allow, and must not write a timestep on deny.

## Code and secret

- `code` must be a string of exactly `policy.digits` decimal digits (6 in the public policy). Anything else, including a shorter string, spaces, or letters, is `bad_code`.
- Decode `secret_base32` as RFC 4648 Base32 (padding `=` is optional). If decoding fails, or the secret is empty after decoding, deny with `bad_secret`. Do not throw out of `verify_totp`.
- The OTP algorithm is TOTP-SHA1: `HOTP(secret, timestep)` as in RFC 4226 / 6238, with `policy.digits` decimal digits.

## Window and replay

- Let `t0 = floor(now / period_seconds)`. With `window` W (1 in the public policy), accept a code that matches the OTP for any timestep in `t0-W ... t0+W` inclusive, checked with a constant-time compare. If none match, `bad_code`.
- If a matching timestep is already present in the ledger for the same `account_id`, deny with `replay`. A timestep used by a different account does not count as replay.
- On allow, `used_timestep` is the matching timestep. If several window slots match (should not happen for distinct timesteps with this algorithm), pick the one closest to `t0`, breaking ties toward `t0` then the smaller timestep.
- `fixtures/ledgers/alice-used-now.json` already records alice's timestep at `1763000000`. Verifying alice's current code against that ledger with `--now 1763000000` must be `replay`. The same code against `fixtures/ledgers/empty.json` must be `allow`.
- `fixtures/accounts/bob.json` has a different secret. Alice's current code must not verify against bob.

## Public expectations (`--now 1763000000`, `fixtures/policy.json`)

- `fixtures/accounts/alice.json` + code `536499` + `fixtures/ledgers/empty.json` → allow, `used_timestep` `58766666`
- The previous-step code `133119` against the empty ledger → allow, `used_timestep` `58766665` (inside the window)
- alice + `536499` + `fixtures/ledgers/alice-used-now.json` → deny / `replay`
- alice + `000000` (unless it happens to equal a window code, which it does not for this secret) → deny / `bad_code`
- `fixtures/accounts/bad-secret.json` with any 6-digit code → deny / `bad_secret`

When you self-check the empty-ledger allow path, copy the empty ledger to a temp file first, because a successful verify will append a used record.

## Exit status

- `allow` → exit 0 (and the CLI appends the ledger)
- `deny` → exit 1 (ledger unchanged)
- Account, policy, or ledger load errors → exit 2, and do not write a report that claims `allow`.
