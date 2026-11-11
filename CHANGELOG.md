# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Dependencies

- Bumped the [nxe-jwx](https://github.com/kjdev/nxe-jwx) submodule from 0.3.0 to 0.4.0
  - Adds `nxe_jwx_jwks_verify_raw_by_kid()` (detached signature verification keyed by raw JWK `kid`); fixes it to try every key sharing a duplicate `kid` instead of only the first match
  - auth_gate's current code paths do not call the new API, so there is no behavioral change

## [0.5.0] - 2026-09-02

### Changed

- Added the [nxe-phase](https://github.com/kjdev/nxe-phase) submodule and switched PRECONTENT phase handler registration to the shared, priority-based registry (`nxe_phase_add_handler`, priority 600). When co-located with sibling modules such as auth-cedar (700), auth-rbac (750), or internal-redirect (900) in the same location block, execution order is now deterministic regardless of `load_module` ordering

### Dependencies

- Bumped the [nxe-jwx](https://github.com/kjdev/nxe-jwx) submodule from 0.2.0 to 0.3.0
  - Adds RFC 7638 JWK thumbprints, `nxe_jwx_jwks_verify_raw()` (detached signature verification), and `nxe_jwx_encode()` (signed JWT issuing); fixes decode size limit enforcement on `nxe_jwx_encode()` output
  - auth_gate's current code paths do not call the new APIs, so there is no behavioral change

### Fixed

- Set `NGX_HTTP_SUBREQUEST_WAITED` on the parallel JWKS-fetch subrequests issued by `auth_gate_jwt_verify`. Without it, the parent request's completion tracking could fail to correctly wait for all JWKS subrequests to finish

## [0.4.2] - 2026-06-04

### Changed

- Bumped the [nxe-json](https://github.com/kjdev/nxe-json) submodule from 0.3.0 to 0.5.0 and the [nxe-jwx](https://github.com/kjdev/nxe-jwx) submodule from 0.1.0 to 0.2.0
  - nxe-json: adds scalar constructors (`nxe_json_deep_copy` / `nxe_json_from_integer` / `nxe_json_from_boolean` / `nxe_json_null`) and `nxe_json_stringify_compact_sorted` (a canonical serializer that emits object keys in ascending byte order); promotes the NUL-termination of `nxe_json_stringify_*` and `nxe_json_string` output to a public contract
  - nxe-jwx: adds `nxe_jwx_jwks_free()` for immediate keyset release (lets callers free key material without relying on a pool cleanup handler, avoiding leaks on a master-process pool that survives config reloads); promotes `nxe_jwx_token_alg()` / `nxe_jwx_token_kid()` returning NUL-terminated `data` to a public contract (inherited from nxe-json 0.5.0's string contract; no implementation change)
  - All of these are API additions and contract clarifications in the underlying libraries; auth_gate's current code paths do not call the new APIs, so there is no behavioral change

## [0.4.1] - 2026-05-18

No functional changes (re-release of 0.4.0).

## [0.4.0] - 2026-05-18

### Added

- Added the [nxe-json](https://github.com/kjdev/nxe-json) submodule (jansson wrapper with built-in size, depth, array, string, and key-count limits) and the [nxe-jwx](https://github.com/kjdev/nxe-jwx) submodule (JWT decode / JWKS parse / JWS signature verification), replacing the in-tree JSON / JWT / JWKS / JWS implementations

### Changed

- Building from source now requires initializing submodules (`git clone --recursive` or `git submodule update --init --recursive`)
- Minimum required jansson version raised to 2.14
- Numeric comparison operators (`gt` / `ge` / `lt` / `le`) are now fail-closed
  - Any integer operand whose magnitude exceeds 2^53 (9,007,199,254,740,992) returns `NGX_ERROR` rather than falling back to a lossy `double` conversion
  - `NaN` / `Infinity` operands also return `NGX_ERROR`
  - Rejected comparisons yield a 403 response by default
- `auth_gate_jwt` accepts **only JSON object** payloads per RFC 7519 section 7.2 (JWTs with a scalar or array root are now rejected at decode time; previously a scalar payload was rejected via field-path detection (403) and an array payload was indexable)
- `auth_gate_jwt_verify` `kid` matching is now fail-closed
  - When the JWT specifies a `kid` and the JWKS contains key(s) with the same `kid`: only those keys are tried (no fallback to other keys; key-confusion protection)
  - When the JWT specifies a `kid` and the JWKS contains no key with that `kid`: fallback is limited to keys **without a `kid`** (keys with a different `kid` are never tried)
- `auth_gate_jwt_verify` rejects empty JWKS responses and JWKS containing only `use=enc` keys at parse time
- Error log strings for `auth_gate_jwt` / `auth_gate_jwt_verify` have changed (the `auth_gate_jwt:` / `auth_gate_jws:` / `auth_gate_jwks:` prefixes are replaced with `nxe_jwx:` prefixes)

## [0.3.0] - 2026-03-11

### Changed

- **BREAKING:** Moved handler from ACCESS phase to PRECONTENT phase to enable coexistence with oidc module in the same location block
  - Phase execution order (ACCESS → PRECONTENT) is guaranteed by nginx architecture, eliminating dependency on `load_module` directive order
  - `satisfy` directive no longer applies to auth_gate (PRECONTENT phase is outside ACCESS phase checker)
- Renamed internal handler function from `ngx_http_auth_gate_access_handler` to `ngx_http_auth_gate_handler` for phase-neutral naming

## [0.2.0] - 2026-03-10

### Added

- Added `auth_gate_jwt_verify` directive for JWT signature verification using JWKS (RS256/384/512, PS256/384/512, ES256/384/512/ES256K, EdDSA)
- Requires OpenSSL 3.0+ for JWT signature verification

### Changed

- **BREAKING:** All auth_gate directives are now skipped in subrequests (previously evaluated in all requests including subrequests)

## [0.1.0] - 2026-03-06

### Added

- Added `auth_gate` directive for variable value comparison and truthiness checking
- Added `auth_gate_json` directive for JSON field validation
- Added `auth_gate_jwt` directive for JWT claim validation (without signature verification)
- Operators: `eq`, `gt`, `ge`, `lt`, `le`, `in`, `any`, `match` with `!` negation prefix
- JQ-like field path syntax for JSON/JWT field access
- Added `$auth_gate_epoch` variable for JWT exp/nbf claim comparison
- Added jansson library dependency for JSON parsing
