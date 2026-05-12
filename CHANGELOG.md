# Changelog

## [447acc5](../../commit/447acc5) - 2026-05-13

### Changed

- Removed the now-unreachable scalar / array / NULL payload guard in `require_validate_jwt` (nxe_jwx_decode enforces RFC 7519 section 7.2 at decode time, leaving the legacy guard as dead code; no behavioral change)

## [aa8b2d8](../../commit/aa8b2d8) - 2026-05-13

### Changed

- Replaced the in-tree JWT decode / JWKS parse / JWS verification implementation (`ngx_auth_gate_jwt` / `_jwks` / `_jws`) with the external [nxe-jwx](https://github.com/kjdev/nxe-jwx) submodule (pinned to the 0.1.0 release)
  - `auth_gate_jwt` accepts **only JSON object** payloads per RFC 7519 section 7.2 (JWTs with a scalar or array root are rejected at decode time; previously a scalar payload was rejected via field-path detection (403) and an array payload was indexable)
  - `auth_gate_jwt_verify` `kid` matching is now fail-closed
    - When the JWT specifies a `kid` and the JWKS contains key(s) with the same `kid`: only those keys are tried (no fallback to other keys; key-confusion protection)
    - When the JWT specifies a `kid` and the JWKS contains no key with that `kid`: fallback is limited to keys **without a `kid`** (keys with a different `kid` are never tried)
  - `auth_gate_jwt_verify` rejects empty JWKS responses and JWKS containing only `use=enc` keys at parse time
  - Error log strings for `auth_gate_jwt` / `auth_gate_jwt_verify` have changed (the `auth_gate_jwt:` / `auth_gate_jws:` / `auth_gate_jwks:` prefixes are replaced with `nxe_jwx:` prefixes)

## [1d59ef5](../../commit/1d59ef5) - 2026-05-13

### Changed

- Bumped the [nxe-json](https://github.com/kjdev/nxe-json) submodule from 0.2.0 to 0.3.0
  - Adds the object iteration API (`nxe_json_object_size`, `nxe_json_object_iter` / `_iter_next` / `_iter_key` / `_iter_value`), which nxe-jwx uses to walk JWKS keyval documents
  - Raises the minimum required jansson version to 2.14 (needed for `json_object_iter_key_len` and related entry points)

## [4981b72](../../commit/4981b72) - 2026-05-13

### Added

- Added the nxe-jwx submodule under `nxe-jwx/` (pinned to 0.1.0)

## [0785a8a](../../commit/0785a8a) - 2026-04-24

### Changed

- Bumped the [nxe-json](https://github.com/kjdev/nxe-json) submodule from 0.1.0 to 0.2.0
  - Existing scalar extractors (`nxe_json_string` / `_integer` / `_real` / `_boolean` / `_number`) and existing object helper (`_object_get_string`) now zero-clear their out-parameters on failure (fail-closed hardening; no behavior change for callers that check the return value)
  - New object helpers (`nxe_json_object_get_integer`, `nxe_json_object_get_boolean`) added upstream with the same zero-clearing behavior built in; not yet used by auth_gate

## [cd64594](../../commit/cd64594) - 2026-04-21

### Changed

- Replaced the in-tree JSON wrapper `ngx_auth_gate_json` with the external [nxe-json](https://github.com/kjdev/nxe-json) submodule (pinned to the 0.1.0 release)
  - Numeric comparison operators (`gt` / `ge` / `lt` / `le`) are now fail-closed
    - Any integer operand whose magnitude exceeds 2^53 (9,007,199,254,740,992) returns `NGX_ERROR` rather than falling back to a lossy `double` conversion
    - `NaN` / `Infinity` operands also return `NGX_ERROR`
    - Rejected comparisons yield a 403 response by default
  - Duplicate keys within a single JSON object are rejected via `JSON_REJECT_DUPLICATES` (unchanged behavior)

## [a42e5b1](../../commit/a42e5b1) - 2026-04-21

### Added

- Add `nxe-json` 0.1.0 submodule under `nxe-json/` (jansson wrapper with built-in size, depth, array, string, and key-count limits)

### Changed

- Building from source now requires initializing the submodule (`git clone --recursive` or `git submodule update --init --recursive`)

## [fb79555](../../commit/fb79555) - 2026-03-23

### Changed

- Removed explicit PCRE library linking from module build configuration
  - Alpine's official nginx package dynamically links libpcre2-8.so, making explicit linking unnecessary
  - PCRE symbols are resolved from the shared library already loaded by the nginx process

## [f76f2c9](../../commit/f76f2c9) - 2026-03-23

### Fixed

- Fixed module failing to load on Alpine Linux (musl) with `pcre_exec: symbol not found` by explicitly linking the PCRE library in the module build configuration

## [1a0a6fe](../../commit/1a0a6fe) - 2026-03-11

### Changed

- Renamed internal handler function from `ngx_http_auth_gate_access_handler` to `ngx_http_auth_gate_handler` for phase-neutral naming

## [86dbd31](../../commit/86dbd31) - 2026-03-11

### Changed

- **BREAKING:** Moved handler from ACCESS phase to PRECONTENT phase to enable coexistence with oidc module in the same location block
  - Phase execution order (ACCESS → PRECONTENT) is guaranteed by nginx architecture, eliminating dependency on `load_module` directive order
  - `satisfy` directive no longer applies to auth_gate (PRECONTENT phase is outside ACCESS phase checker)

## [a2306ae](../../commit/a2306ae) - 2026-03-10

### Added

- Added `auth_gate_jwt_verify` directive for JWT signature verification using JWKS (RS256/384/512, PS256/384/512, ES256/384/512/ES256K, EdDSA)
- Requires OpenSSL 3.0+ for JWT signature verification

### Changed

- **BREAKING:** All auth_gate directives are now skipped in subrequests (previously evaluated in all requests including subrequests)

## [b32c3a5](../../commit/b32c3a5) - 2026-03-06

### Changed

- **BREAKING:** Renamed module from `auth_require` to `auth_gate` (all directives and module name)
  - `auth_require` → `auth_gate`
  - `auth_require_json` → `auth_gate_json`
  - `auth_require_jwt` → `auth_gate_jwt`
  - `$auth_require_epoch` → `$auth_gate_epoch`

## [4c1b162](../../commit/4c1b162) - 2026-02-26

### Added

- Added `auth_require` directive for variable value comparison and truthiness checking
- Added `auth_require_json` directive for JSON field validation
- Added `auth_require_jwt` directive for JWT claim validation (without signature verification)
- Operators: `eq`, `gt`, `ge`, `lt`, `le`, `in`, `any`, `match` with `!` negation prefix
- JQ-like field path syntax for JSON/JWT field access
- Added `$auth_require_epoch` variable for JWT exp/nbf claim comparison
- Added jansson library dependency for JSON parsing

