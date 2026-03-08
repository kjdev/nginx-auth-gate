# Security Considerations

Security guidelines for safely using the nginx auth_gate module.

## JWT Signature Verification

This module provides the `auth_gate_jwt_verify` directive for JWT signature verification using JWKS. When using `auth_gate_jwt` for claim validation, always pair it with `auth_gate_jwt_verify` or an external authentication module to ensure tokens are signature-verified.

The `auth_gate_jwt` directive **does not perform JWT signature verification** on its own. It only base64url decodes the JWT payload and validates claim values.

**Tampering risk**: When using HTTP header or cookie values directly as JWT without signature verification, clients can freely tamper with the payload. For example:

- If you pass `$http_authorization` or `$cookie_token` directly to `auth_gate_jwt` without `auth_gate_jwt_verify`, an attacker can send a JWT with arbitrary claim values
- Simply base64url encoding a payload like `{"role": "admin"}` and setting it in a header could bypass authorization checks

**Recommended configuration**: Use `auth_gate_jwt_verify` to verify signatures, then validate claims with `auth_gate_jwt`.

```nginx
http {
    # Strip Bearer prefix from Authorization header
    map $http_authorization $bearer_token {
        default "";
        ~*^Bearer\s+(?<t>.+)$ $t;
    }

    server {
        location = /jwks {
            internal;
            proxy_set_header Accept-Encoding "";
            proxy_pass https://idp.example.com/.well-known/jwks.json;
        }

        location /api {
            # Step 1: Verify JWT signature
            auth_gate_jwt_verify $bearer_token jwks=/jwks;

            # Step 2: Validate claim values of signature-verified tokens
            auth_gate_jwt $bearer_token .role eq "admin" error=403;
            proxy_pass http://backend;
        }
    }
}
```

Alternatively, you can delegate signature verification to an external authentication module (`auth_jwt`, `oidc`, etc.) and validate claims against their output variables.

### Dangerous Variable Patterns

The following variables, when passed directly to `auth_gate_jwt` **without** `auth_gate_jwt_verify`, allow clients to bypass claim validation using tampered JWTs:

| Variable | Risk |
|----------|------|
| `$http_authorization` | Authorization header value (client can set arbitrarily) |
| `$cookie_*` | Cookie values (client can set arbitrarily) |
| `$arg_*` | Query parameters (can be set arbitrarily via URL) |
| `$http_x_*` | Custom headers (client can set arbitrarily) |

### Safe Variable Patterns

| Variable | Reason |
|----------|--------|
| `$oidc_id_token` / `$oidc_access_token` | Raw JWTs whose signatures were already verified by the oidc module |
| Variables set by upstream modules | Safe for `auth_gate_jwt` only when they still contain the raw JWT after upstream verification |

For already-decoded payload variables such as `$jwt_payload` from `auth_jwt`, use `auth_gate_json` instead of `auth_gate_jwt`.

**Dangerous configuration example** (using external input directly without signature verification):
```nginx
# BAD: Using an unverified Cookie value directly -- tamperable
location /api {
    set $token $cookie_access_token;
    auth_gate_jwt $token .role eq "admin" error=403;  # Can be bypassed!
    proxy_pass http://backend;
}

# OK: Verify signature first, then validate claims
location /api {
    set $token $cookie_access_token;
    auth_gate_jwt_verify $token jwks=/jwks;           # Signature verified
    auth_gate_jwt $token .role eq "admin" error=403;  # Safe
    proxy_pass http://backend;
}
```

### auth_gate_jwt_verify Security Notes

- The `none` algorithm is explicitly rejected to prevent algorithm confusion attacks
- HMAC algorithms (`HS256`, `HS384`, `HS512`) are rejected because symmetric key verification is not appropriate for JWKS-based public key verification
- Key selection uses `kid` when the JWT header provides one, and always filters candidate JWKS keys by `alg` compatibility and key type (`kty`) to prevent algorithm confusion attacks
- JWKS response size is limited to 256 KiB and key count to 64 to prevent resource exhaustion
- Key validation: RSA minimum key length 2048 bit, EC coordinate length validation (P-256/secp256k1: 32, P-384: 48, P-521: 66), EdDSA public key length validation (Ed25519: 32, Ed448: 57)

Supported algorithms (whitelist approach):

| Family | Algorithms |
|--------|-----------|
| RSA PKCS#1 v1.5 | `RS256`, `RS384`, `RS512` |
| RSA PSS | `PS256`, `PS384`, `PS512` |
| ECDSA | `ES256`, `ES384`, `ES512`, `ES256K` |
| EdDSA | `EdDSA` (Ed25519, Ed448) |

### JWKS Location Best Practices

**Always use `internal`**: The JWKS location **must** include the `internal` directive. Without it, external clients can directly access the JWKS endpoint, which may expose information about your key infrastructure or allow abuse of the upstream IdP connection.

```nginx
# CORRECT: internal prevents direct client access
location = /jwks {
    internal;
    proxy_set_header Accept-Encoding "";
    proxy_pass https://idp.example.com/.well-known/jwks.json;
}

# WRONG: accessible to external clients
location = /jwks {
    proxy_pass https://idp.example.com/.well-known/jwks.json;
}
```

**Always use `proxy_cache`**: Without caching, every incoming request triggers a subrequest to the JWKS endpoint. This creates unnecessary load on the upstream IdP and adds latency to every request. Use `proxy_cache` to cache the JWKS response.

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

A cache lifetime of 1 hour is recommended as a balance between key rotation responsiveness and performance. Adjust based on your IdP's key rotation frequency.

## Regular Expression Denial of Service (ReDoS) Protection

The `match` operator uses PCRE regular expressions. The following protections are implemented to defend against backtracking attacks (ReDoS) caused by malicious patterns or input.

### match_limit Restriction

PCRE match_limit and depth_limit are set for all regular expression matches (both constant and dynamic patterns):

| Parameter | Value | Description |
|-----------|-------|-------------|
| `match_limit` | 100,000 | Upper limit on backtracking attempts |
| `depth_limit` | 100,000 | Upper limit on recursion depth |

When the limit is exceeded, the match is treated as a failure (403 response by default).

### Dynamic Pattern Risks

When using nginx variables in `match` operator patterns, regular expression compilation and execution occur per request. This has both performance costs and security risks:

- **Performance**: Compilation cost incurred per request
- **Pattern size**: Dynamic patterns are limited to 8,192 bytes
- **Compilation count**: Dynamic pattern compilations are limited to 16 per request
- **Configuration warning**: Dynamic pattern usage is logged at `WARN` level

**Recommendation**: Use constant patterns whenever possible. Constant patterns are precompiled during configuration parsing, eliminating per-request compilation costs.

### Unsafe Configuration Patterns

Using external input (user-controllable values) as `match` operator patterns is dangerous:

```nginx
# BAD: Using user input as a pattern -- ReDoS attack possible
auth_gate $variable match $arg_pattern;

# OK: Validating user input with a constant pattern
auth_gate $variable match "^[a-zA-Z0-9_]+$";
```

## DoS Defense Mechanisms

The module has the following limit values implemented:

| Limit | Value | Target |
|-------|-------|--------|
| JSON parse size limit | 1 MiB | Input data for `auth_gate_json` / `auth_gate_jwt` |
| JWT token size limit | 16 KiB | Token length for `auth_gate_jwt` |
| Expected value size limit | 64 KiB | Byte size of `<expected>` value |
| Array size limit | 1,024 | Array element count for `in` / `any` operators |
| Comparison count limit | 10,000 | O(n*m) comparison count for `any` operator |
| Field path depth | 32 | Number of field path segments |
| Array index limit | 65,535 | Array index value in field paths |
| Regex match_limit | 100,000 | PCRE backtracking attempt count |
| Regex depth_limit | 100,000 | PCRE recursion depth |
| Dynamic pattern size | 8,192 bytes | Maximum length of dynamic `match` patterns |
| Dynamic regex compilation limit | 16/request | Compilation count of dynamic `match` patterns |

All limit exceedances return `NGX_ERROR`, resulting in a 403 response by default.

## Numeric Comparison Precision

Numeric comparison operators such as `gt`, `ge`, `lt`, `le` follow these precision rules:

| Case | Comparison Method | Precision |
|------|-------------------|-----------|
| Both integers | Direct `int64_t` comparison | Full precision (up to 2^63-1) |
| Integer/real mixed (real has integer value) | Convert to `int64_t` and compare | Full precision |
| Integer/real mixed (real has fractional value) | Fallback to `double` | Possible precision loss above 2^53 |
| Both reals | `double` comparison | IEEE 754 double precision |

For UNIX timestamp comparisons such as JWT `exp` / `nbf` claims, direct integer-to-integer comparison is used, so there are no precision issues.

## Input Validation

- Field paths are validated during nginx configuration parsing. Invalid path syntax results in an error at module load time
- Operator names are also validated during configuration parsing. Unknown operators result in an error
- The `error=` parameter only accepts values in the 4xx/5xx range (444/499 are rejected as nginx internal codes)

## Error Code Design

It is recommended to use different error codes for authentication and authorization:

| Status Code | Use | Example |
|-------------|-----|---------|
| `401` | Authentication error (user not identified) | `auth_gate $oidc_claim_sub error=401;` |
| `403` | Authorization error (insufficient permissions) | `auth_gate_json $claims .role eq "admin" error=403;` |

## Known Limitations

### Stack Overflow from Deeply Nested JSON

The `eq` operator internally uses the Jansson library's `json_equal()` function for deep equality comparison of JSON values. This function operates recursively, so comparing extremely nested JSON structures (thousands of levels or more) can exhaust the process's stack space and cause the worker process to crash.

**Impact**: The nginx worker process crashes with SIGSEGV, temporarily interrupting request processing. The nginx master process automatically restarts workers, so it does not result in a complete service outage.

**Risk assessment**: While the JSON parse size limit (1 MiB) effectively constrains nesting depth, patterns like `[[[[...` using 2 bytes per level could produce approximately 500,000 levels of nesting. With a typical stack size (8 MB), exhaustion occurs at approximately 60,000-120,000 levels, so the size limit alone is not a complete defense.

**Mitigation**:

- A recursion depth limit in the Jansson library would be the fundamental solution, but Jansson currently does not provide this feature
- Avoid configurations that pass user-controllable input to **both sides** (both actual and expected) of the `eq` operator
- In normal usage, the expected side is a constant value or an administrator-controlled variable, making this issue unlikely to occur

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Quick start and practical configuration examples
- [INSTALL.md](INSTALL.md): Installation guide (prerequisites, build instructions)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting (common issues, log inspection)
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial auth_require compatibility
