# Report schema

```json
{
  "decision": "allow",
  "reason_codes": [],
  "account_id": "alice",
  "used_timestep": 58766666
}
```

- `decision` is `allow` or `deny`.
- `reason_codes` is empty on `allow`. On `deny` it contains one or more of `bad_code`, `bad_secret`, `replay`.
- `account_id` is copied from the account file.
- `used_timestep` is the consumed timestep on `allow`, and `null` on `deny`.
