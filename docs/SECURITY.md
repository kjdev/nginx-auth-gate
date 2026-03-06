# Security Considerations

Security guidelines for safely using the nginx auth_gate module.

## JWT Signature Verification

The `auth_gate_jwt` directive **does not perform JWT signature verification**. It only base64url decodes the JWT payload and validates claim values.

JWT authentication (signature verification) is the responsibility of authentication modules such as `auth_jwt` and `auth_oidc`. `auth_gate_jwt` handles only authorization (validation of claim values).

**Tampering risk**: When using HTTP header or cookie values directly as JWT without signature verification, clients can freely tamper with the payload. For example:

- If you pass `$http_authorization` or `$cookie_token` directly to `auth_gate_jwt`, an attacker can send a JWT with arbitrary claim values
- Simply base64url encoding a payload like `{"role": "admin"}` and setting it in a header could bypass authorization checks

**Recommended configuration**: Always perform signature verification with an upstream authentication module and validate claims against **signature-verified tokens**.

```nginx
server {
    # Authentication: perform JWT signature verification with auth_oidc or auth_jwt
    # auth_oidc my_idp;

    location /api {
        # Authorization: validate claim values of signature-verified tokens
        auth_gate_jwt $token .role eq "admin" error=403;
        proxy_pass http://backend;
    }
}
```

### Dangerous Variable Patterns

The following variables, when passed directly to `auth_gate_jwt`, allow clients to bypass claim validation using tampered JWTs:

| Variable | Risk |
|----------|------|
| `$http_authorization` | Authorization header value (client can set arbitrarily) |
| `$cookie_*` | Cookie values (client can set arbitrarily) |
| `$arg_*` | Query parameters (can be set arbitrarily via URL) |
| `$http_x_*` | Custom headers (client can set arbitrarily) |

### Safe Variable Patterns

| Variable | Reason |
|----------|--------|
| `$oidc_id_token` / `$oidc_access_token` | Signature verified by auth_oidc module |
| `$jwt_payload` | Signature verified by auth_jwt module |
| Variables set by upstream modules | Values verified upstream |

**Dangerous configuration example** (using external input directly without signature verification):
```nginx
# BAD: Using an unverified Cookie value directly -- tamperable
location /api {
    set $token $cookie_access_token;
    auth_gate_jwt $token .role eq "admin" error=403;  # Can be bypassed!
    proxy_pass http://backend;
}
```

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
