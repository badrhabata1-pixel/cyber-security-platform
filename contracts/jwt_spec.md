# JWT Contract

Owner: Person 4 (Platform). Consumers: all modules that validate platform tokens.

| Item      | Value |
|-----------|-------|
| Algorithm | `HS256` |
| Secret    | Environment variable `JWT_SECRET` (default fallback: `dev_jwt_secret_change_in_prod`) |
| Header    | `Authorization: Bearer <token>` |

## Claims

| Claim  | Type   | Description |
|--------|--------|-------------|
| `sub`  | string | User email |
| `role` | string | One of `admin`, `analyst`, `viewer` |
| `exp`  | int    | Expiry as a UTC UNIX timestamp (seconds) |

## Errors

- `401 Unauthorized`: missing, malformed, invalid or expired token.
- `403 Forbidden`: valid token, but the role is not allowed for the endpoint.

All timestamps across the platform are UTC, ISO 8601.
