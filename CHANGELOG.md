# Changelog

## [a2306ae] - 2026-03-10

### Added

- `auth_gate_jwt_verify` directive for JWT signature verification using JWKS (RS256/384/512, PS256/384/512, ES256/384/512/ES256K, EdDSA)
- OpenSSL 3.0+ dependency for JWT signature verification

### Changed

- **BREAKING:** All auth_gate directives are now skipped in subrequests (previously evaluated in all requests including subrequests)

## [b32c3a5] - 2026-03-06

### Changed

- **BREAKING:** Renamed module from `auth_require` to `auth_gate` (all directives and module name)
  - `auth_require` → `auth_gate`
  - `auth_require_json` → `auth_gate_json`
  - `auth_require_jwt` → `auth_gate_jwt`
  - `$auth_require_epoch` → `$auth_gate_epoch`

## [4c1b162] - 2026-02-26

### Added

- `auth_require` directive for variable value comparison and truthiness checking
- `auth_require_json` directive for JSON field validation
- `auth_require_jwt` directive for JWT claim validation (without signature verification)
- Operators: `eq`, `gt`, `ge`, `lt`, `le`, `in`, `any`, `match` with `!` negation prefix
- JQ-like field path syntax for JSON/JWT field access
- `$auth_require_epoch` variable for JWT exp/nbf claim comparison
- jansson library dependency for JSON parsing

[a2306ae]: https://github.com/kjdev/nginx-auth-gate/commit/a2306ae
[b32c3a5]: https://github.com/kjdev/nginx-auth-gate/commit/b32c3a5
[4c1b162]: https://github.com/kjdev/nginx-auth-gate/commit/4c1b162
