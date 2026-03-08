# Directive and Variable Reference

Reference for directives, operators, field path syntax, and embedded variables provided by the nginx auth_gate module. See [EXAMPLES.md](EXAMPLES.md) for configuration examples and [README.md](../README.md) for a module overview.

## Configuration Examples

Practical configuration examples are available in [EXAMPLES.md](EXAMPLES.md).

## Directives

This module provides the following directives. There are 8 operators: `eq`, `gt`, `ge`, `lt`, `le`, `in`, `any`, and `match`, with negation possible via the `!` prefix.

| Directive | Syntax | Function |
|---|---|---|
| [`auth_gate`](#auth_gate-comparison--truthiness-check) | `$var <op> <expected> [error=...]` | Operator-based variable value comparison |
| | `$var [...] [error=...]` | Variable truthiness check |
| [`auth_gate_json`](#auth_gate_json-json-field-validation) | `$var <field> <op> <expected> [error=...]` | JSON variable field validation |
| [`auth_gate_jwt`](#auth_gate_jwt-jwt-claim-validation) | `$var <claim> <op> <expected> [error=...]` | JWT claim validation (no signature verification) |
| [`auth_gate_jwt_verify`](#auth_gate_jwt_verify-jwt-signature-verification) | `$var jwks=<uri> [error=...]` | JWT signature verification using JWKS |

### auth_gate (Comparison / Truthiness Check)

```
Syntax:  auth_gate $variable <operator> <expected> [error=4xx|5xx];
         auth_gate $variable [...] [error=4xx|5xx];
Default: —
Context: http, server, location, limit_except
```

Operates in two modes.

#### Comparison Mode

When an operator is specified, validates a single variable's value using the operator. The variable value is treated as a string and compared against the expected value. The expected value can also be specified as a JSON value using the `json=` prefix (see [Expected Value Type Specification](#expected-value-type-specification)).

**Constraint**: In comparison mode, only one variable is allowed. Mixing multiple variables with operators is prohibited.

```nginx
# Equality comparison
auth_gate $arg_role eq "admin" error=403;

# Negation
auth_gate $upstream_status !eq "200";

# Check if contained in array
auth_gate $arg_type in json=["staff","admin"] error=403;

# Regular expression match
auth_gate $http_x_api_key match "^sk-[a-zA-Z0-9]+$" error=401;
```

#### Truthiness Check Mode

When no operator is specified, verifies that all specified variables satisfy the following conditions:
- Not an empty string
- Not `"0"`

Multiple variables can be specified. If any condition is not satisfied, the status code specified by `error` is returned (default: `403`). This mode behaves equivalently to the [`auth_require` directive from the nginx commercial subscription](https://nginx.org/en/docs/http/ngx_http_auth_require_module.html).

```nginx
# Single variable truthiness check
auth_gate $oidc_claim_sub error=401;

# Multiple variable AND check
auth_gate $is_admin $has_permission error=403;
```

**Mode determination**: If the second argument starts with `$`, it is interpreted as multiple variable mode (truthiness check). If it starts with `error=`, it is an error code specification. Otherwise, it is interpreted as comparison mode.

#### Configuration Merging

Multiple `auth_gate` directives can be specified. Each directive is evaluated independently, and if any one fails, the corresponding error code is returned (AND condition).

When defined in both a parent context (server) and a child context (location), the parent's requirements are prepended and the child's requirements are appended.

```nginx
server {
    auth_gate $oidc_claim_sub error=401;  # Base requirement

    location /admin {
        auth_gate $is_admin error=403;  # Additional requirement
        # Merge result: $oidc_claim_sub (401) AND $is_admin (403)
    }
}
```

### auth_gate_json (JSON Field Validation)

```
Syntax:  auth_gate_json $variable <field> <operator> <expected>
                           [error=4xx|5xx];
Default: —
Context: http, server, location, limit_except
```

Parses the variable value as JSON and validates the field specified by `<field>` using the `<operator>`.

- `<field>`: JQ-like field path (see [Field Path Syntax](#field-path-syntax)). Must start with `.`
- `<operator>`: Comparison operator (see [Operators](#operators))
- `<expected>`: Expected value. Can include variables. Use the `json=` prefix to specify JSON values (see [Expected Value Type Specification](#expected-value-type-specification))
- `error`: HTTP status code to return on validation failure (default: `403`)

```nginx
# Root value comparison (. = root)
auth_gate_json $oidc_claim_role . eq "admin" error=403;

# Field specification
auth_gate_json $oidc_claims .role eq "admin" error=403;

# Numeric comparison (specify as JSON number with json= prefix)
auth_gate_json $oidc_claims .age ge json=18;

# Comparison with JSON value (json= prefix)
auth_gate_json $oidc_claims .groups any json=["staff","admin"];

# Nested fields
auth_gate_json $oidc_claims .user.profile.role eq "admin";

# Array element access
auth_gate_json $oidc_claims .keys[0] eq "primary";

# Field name containing dots (quoted bracket notation)
auth_gate_json $oidc_claims .["https://example.com/roles"] any json=["admin"];

# Regular expression match
auth_gate_json $oidc_claims .email match "^.*@example\\.com$";
```

### auth_gate_jwt (JWT Claim Validation)

```
Syntax:  auth_gate_jwt $variable <claim> <operator> <expected>
                          [error=4xx|5xx];
Default: —
Context: http, server, location, limit_except
```

Decodes the variable value as a JWT token (base64url decode) and validates claims in the payload.

**No signature verification is performed**. JWT authentication (signature verification) is the responsibility of `auth_gate_jwt_verify`, `auth_jwt`, `oidc`, or similar modules. This directive handles only authorization (validation of claim values).

JWT decode process:
1. Split the token by `.`
2. Base64url decode the second segment (payload)
3. Parse the decoded result as JSON
4. Apply the same field validation logic as `auth_gate_json`

```nginx
# Use a signature-verified token variable (see SECURITY.md)
set $token $oidc_access_token;

auth_gate_jwt $token .sub !eq "" error=401;
auth_gate_jwt $token .scope any json=["api:read","api:write"] error=403;

# Nested claims
auth_gate_jwt $token .resource_access.my-app.roles any json=["admin"];

# Special keys (URL-format claim names)
auth_gate_jwt $token .["https://example.com/roles"] any json=["admin"];
```

**Security note**: This directive does not perform JWT signature verification. If you use a JWT token obtained from HTTP headers or cookies directly as a validation source, there is a risk of payload tampering by clients. Either use `auth_gate_jwt_verify` to verify signatures, or perform signature verification using an upstream authentication module (`auth_jwt`, `oidc`, etc.) before use. See [SECURITY.md](SECURITY.md) for details.

### auth_gate_jwt_verify (JWT Signature Verification)

```
Syntax:  auth_gate_jwt_verify $variable jwks=<uri> [error=4xx|5xx];
Default: —
Context: http, server, location, limit_except
```

Verifies the JWT signature of the token stored in `$variable` using public keys fetched from a JWKS (JSON Web Key Set) endpoint.

- `$variable`: nginx variable containing the raw JWT token (without `Bearer ` prefix). If using the `Authorization` header, strip the prefix with `map` first (see [EXAMPLES.md](EXAMPLES.md))
- `jwks=<uri>`: Internal location URI that returns JWKS JSON. Must start with `/`
- `error`: HTTP status code to return on verification failure (default: `401`)

The JWKS is fetched via an nginx subrequest to the specified URI. The JWKS location **must** use the `internal` directive to prevent direct external access. Without `internal`, clients could probe the JWKS endpoint directly, potentially leaking information about your key infrastructure.

**Supported algorithms**:

| Algorithm Family | Algorithms | Key Type |
|-----------------|------------|----------|
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 | RSA |
| RSA-PSS | PS256, PS384, PS512 | RSA |
| ECDSA | ES256, ES384, ES512, ES256K | EC (P-256, P-384, P-521, secp256k1) |
| EdDSA | EdDSA | OKP (Ed25519, Ed448) |

The `none` algorithm and HMAC algorithms (`HS256`, `HS384`, `HS512`) are explicitly rejected.

**Key matching**: Keys are matched by `kid` (Key ID), `alg` (algorithm), and `kty` (key type). When the JWT header contains a `kid`, only keys with a matching `kid` are tried. When the JWT header does not contain a `kid`, all keys with compatible `alg` and `kty` are tried. If no compatible key is found, verification fails.

```nginx
# JWKS endpoint (internal location proxying to IdP)
location = /jwks {
    internal;
    proxy_set_header Accept-Encoding "";
    proxy_pass https://idp.example.com/.well-known/jwks.json;
}

# Verify JWT signature then check claims
# See the map definition in EXAMPLES.md for stripping the Bearer prefix
location /api {
    auth_gate_jwt_verify $bearer_token jwks=/jwks;
    auth_gate_jwt $bearer_token .role eq "admin" error=403;
    proxy_pass http://backend;
}

# Multiple tokens with different JWKS endpoints
location /federated {
    auth_gate_jwt_verify $cookie_id_token jwks=/jwks_idp_a;
    auth_gate_jwt_verify $http_x_service_token jwks=/jwks_idp_b;
    proxy_pass http://backend;
}
```

**Subrequest deduplication**: When multiple `auth_gate_jwt_verify` directives reference the same `jwks=` URI, only one subrequest is issued and the response is shared.

**JWKS caching**: Without caching, a subrequest to the JWKS endpoint is issued for every request. In production, **always** use `proxy_cache` to cache the JWKS response and avoid unnecessary upstream requests. A typical JWKS cache lifetime of 1 hour balances key rotation responsiveness with performance.

```nginx
proxy_cache_path /var/cache/nginx/jwks levels=1 keys_zone=jwks_cache:1m;

location = /jwks {
    internal;
    proxy_set_header Accept-Encoding "";
    proxy_cache jwks_cache;
    proxy_cache_valid 200 1h;
    proxy_pass https://idp.example.com/.well-known/jwks.json;
}
```

**JWKS limits**:

| Limit | Value |
|-------|-------|
| JWKS response size | 256 KiB |
| Maximum keys in JWKS | 64 |

## Operators

Use 8 affirmative operators combined with negation via the `!` prefix.

| Operator | Negation | Meaning | Input Type | Expected Type |
|----------|----------|---------|------------|---------------|
| `eq` | `!eq` | Equal / Not equal | All types | Same type |
| `gt` | — | Greater than | Numeric/String | Numeric/String |
| `ge` | — | Greater than or equal | Numeric/String | Numeric/String |
| `lt` | — | Less than | Numeric/String | Numeric/String |
| `le` | — | Less than or equal | Numeric/String | Numeric/String |
| `in` | `!in` | Value contained in array/object | Value | Array/Object |
| `any` | `!any` | Common elements between arrays | Array | Array |
| `match` | `!match` | Regular expression match | String | String (regex pattern) |

### in Operator Behavior

Behavior varies depending on the expected value type:

- When the expected value is an **array**: Validates whether the input value matches any element in the array
- When the expected value is an **object**: Validates whether the input value (string) matches any **key** of the object

### Comparison Operator Type Conversion

`gt`/`ge`/`lt`/`le` prioritize numeric comparison. If both operands are not numeric, it falls back to string comparison (lexicographic order). If one is numeric and the other is a string, the comparison fails (validation failure).

### match Operator Applications

The `match` operator uses nginx/PCRE regular expressions. nginx must be built with PCRE support (`--with-pcre` option). Without PCRE, the `match` operator is unavailable.

`contains` (substring search), `prefix` (prefix match), and `suffix` (suffix match) can all be expressed using `match`:

| Use Case | `match` Expression |
|----------|-------------------|
| Contains | `match "substring"` |
| Prefix match | `match "^prefix"` |
| Suffix match | `match "suffix$"` |
| Complex pattern | `match "^[a-z]+@example\\.com$"` |

> **Note**: nginx's configuration parser interprets `$` as a variable prefix, so using `$` as a regex end-of-string anchor will cause a configuration error. Use PCRE's `\z` (end-of-string anchor) instead:
>
> ```nginx
> # BAD: $ is interpreted as a variable prefix by nginx
> auth_gate $var match "^admin$";
>
> # OK: \z is PCRE's end-of-string anchor
> auth_gate $var match "^admin\\z";
> ```

### Negation Mechanism

Prepending `!` to an operator name inverts the result. Negation is syntactically possible for all operators, but negation of comparison operators (`gt`/`ge`/`lt`/`le`) is typically not meaningful, which is why they are shown as `—` in the table.

## Field Path Syntax

Field paths use JQ-like syntax to specify fields and array elements within JSON values. **They always start with `.`**.

| Notation | Example | Interpretation |
|----------|---------|----------------|
| Root | `.` | Entire JSON value |
| Simple key | `.role` | Top-level `["role"]` |
| Dot-separated | `.user.profile.role` | Nested `["user"]["profile"]["role"]` |
| Array index | `.keys[0]` | First element of `["keys"]` |
| Root array | `.[0]` | First element of root array |
| Quoted bracket | `.["https://example.com/role"]` | Key containing special characters |
| Compound path | `.users[0].name` | `["users"][0]["name"]` |

**Why the `.` prefix is required**: For parser disambiguation. Tokens starting with `.` are uniquely identified as field paths, and tokens starting with operator keywords are identified as operators. This allows fields named `eq` or `match` to be handled without issues.

**Parse grammar**:

```
field_path := "."                       /* root */
            | "." first rest*           /* path */

first      := identifier                /* key */
            | bracket                   /* [0] or ["key"] */

rest       := "." identifier            /* .key */
            | bracket                   /* [0] or ["key"] */

bracket    := "[" integer "]"           /* [0] */
            | '["' string '"]'          /* ["special.key"] */

identifier := [a-zA-Z_][a-zA-Z0-9_-]*
integer    := [0-9]+
string     := (any character, " escaped as \")
```

## Expected Value Type Specification

The expected value (`<expected>`) can be specified in the following ways:

| Specification | Example | Interpretation |
|--------------|---------|----------------|
| Literal string | `"admin"` | JSON string `"admin"` |
| nginx variable | `$expected_role` | Variable value treated as JSON string |
| `json=` prefix | `json=["a","b"]` | Everything after `=` parsed as JSON |
| Numeric literal | `18` | Treated as JSON string `"18"` (use `json=18` for numeric comparison) |

**`json=` prefix**: Used to specify non-string types such as JSON arrays, objects, and booleans. To parse a variable value as JSON, write `json=$variable`.

```nginx
# JSON array
auth_gate_json $claims .roles any json=["admin","staff"];

# JSON boolean
auth_gate_json $claims .email_verified eq json=true;

# JSON object
auth_gate_json $claims .metadata eq json={"key":"value"};
```

## Undefined/Empty Variable Behavior

When an nginx variable is undefined or empty, each directive handles it as follows:

| Context | Behavior |
|---------|----------|
| `auth_gate` truthiness check | Empty string = false (validation fails, returns `error` code) |
| `auth_gate` comparison mode | Treated as empty string `""` and compared with operator |
| `auth_gate_json` | Empty string -> JSON parse failure -> returns `error` code |
| `auth_gate_jwt` | Empty string -> JWT decode failure -> returns `error` code |
| Expected value (`<expected>`) | Treated as empty string `""` and compared as JSON string `""` |

> **Note**: Undefined variables are evaluated as empty strings per nginx specification. For `auth_gate_json` and `auth_gate_jwt`, empty variables result in parse/decode errors and are safely handled in a fail-closed manner.

## Evaluation Order and Grouping

### Evaluation Order

Directives are evaluated in the following order. When any validation fails, short-circuit evaluation (skipping remaining validations) returns the error code of the failed directive:

1. `auth_gate_jwt_verify` (JWT signature verification — async via subrequest)
2. `auth_gate` (truthiness check mode)
3. `auth_gate` (comparison mode)
4. `auth_gate_json`
5. `auth_gate_jwt`

This order is fixed and does not depend on the order of directives in the configuration file. `auth_gate_jwt_verify` runs first because it requires asynchronous JWKS fetching. This ensures that signature verification is complete before any claim validation.

### Variable Grouping

For `auth_gate_json` and `auth_gate_jwt`, **directives referencing the same variable are automatically grouped**. Within a group, the variable value is parsed (JSON parse / JWT decode) only once, and multiple requirements are validated sequentially.

```nginx
# The following 3 directives form 1 group under $oidc_claims
auth_gate_json $oidc_claims .role eq "admin" error=403;
auth_gate_json $oidc_claims .email_verified eq json=true error=403;
auth_gate_json $oidc_claims .age ge json=18 error=403;
```

### Grouping and Error Codes

Due to grouping, the error code returned during short-circuit evaluation may differ from the intended code:

- **When an individual requirement fails**: The `error` code specified for that requirement is returned
- **When JSON parse / JWT decode fails**: The `error` code of the **first requirement in the group** is returned

```nginx
# If JSON parsing fails within the group, the first requirement's error code (error=403) is returned
auth_gate_json $claims .role eq "admin" error=403;
auth_gate_json $claims .sub !eq "" error=401;
```

If you need strict control with different error codes, consider using different variable names to separate groups.

## Directive Selection Guide

| Scenario | Recommended Directive |
|----------|----------------------|
| Just verify a variable is not empty | `auth_gate $var` (truthiness mode) |
| Variable is a simple string value and you want to compare with operators | `auth_gate $var <op> <expected>` |
| Variable is a JSON string and you want to validate specific fields | `auth_gate_json` |
| Variable is a JWT token and you want to validate claims | `auth_gate_jwt` |

## Limits

Each directive and operator has limit values configured for DoS defense. Key limits that may affect operations:

- JSON parse size limit: 1 MiB (input data for `auth_gate_json` / `auth_gate_jwt`)
- JWT token size limit: 16 KiB (token length for `auth_gate_jwt`)
- Array element count limit for `in` / `any` operators: 1,024
- Field path depth limit: 32 segments; array index limit: 65,535
- `error=` parameter: range 400-599 (444/499 rejected as nginx internal codes)

See [SECURITY.md](SECURITY.md) for the complete list of limits and security details.

## Embedded Variables

### $auth_gate_epoch

**Description**: Variable that returns the current UNIX epoch time (seconds)

**Value**: Timestamp at the time of request processing (e.g., `1740000000`)

**Purpose**: Used for comparing against time-based claims such as JWT `exp` (expiration time) and `nbf` (not before time) with the current time.

**Usage examples**:
```nginx
# JWT expiration check (exp > current time)
auth_gate_jwt $token .exp gt json=$auth_gate_epoch error=401;

# JWT not-before check (nbf <= current time)
auth_gate_jwt $token .nbf le json=$auth_gate_epoch;
```

By adding the `json=` prefix, the variable value is parsed as a number in JSON, enabling correct comparison with numeric JWT claims.

**Characteristics**:
- `NGX_HTTP_VAR_NOCACHEABLE`: Re-evaluated for each request (not cached)

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [EXAMPLES.md](EXAMPLES.md): Quick start and practical configuration examples
- [INSTALL.md](INSTALL.md): Installation guide (prerequisites, build instructions)
- [SECURITY.md](SECURITY.md): Security considerations (JWT signature verification, input validation)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting (common issues, log inspection)
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial auth_require compatibility
