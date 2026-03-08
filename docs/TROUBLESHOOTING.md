# Troubleshooting

Problem-solving guide for the nginx auth_gate module.

## Common Issues and Solutions

### Issue 1: Validation Always Fails (403 Returned)

**Symptom**: `auth_gate` returns 403 even with correct values

**Cause**: Variable is empty or has not yet been evaluated

**Solution**:
1. Check variable values with debug logging:
```nginx
error_log /var/log/nginx/error.log debug;
```

2. Verify that the upstream authentication module is correctly setting the variables (values appear in debug-level error log):
```nginx
# Variable values are logged at debug level when auth_gate evaluates them
error_log /var/log/nginx/error.log debug;
```

### Issue 2: JSON Parse Error

**Symptom**: JSON parsing fails with `auth_gate_json`

**Cause**: Variable value is not valid JSON

**Solution**:
1. Verify that the variable value is a JSON string (watch for surrounding whitespace and escaping)
2. Verify that the `json=` prefixed expected value is valid JSON

### Issue 3: Field Not Found

**Symptom**: The specified field does not exist in `auth_gate_json`

**Cause**: JSON structure does not match the specified field path

**Solution**:
1. Verify the JSON structure and check that the field path is correct
2. For nested fields, verify that intermediate keys are correct:
```nginx
# BAD: when .roles is an object, not an array
auth_gate_json $claims .roles[0] eq "admin";

# OK: specify the correct path
auth_gate_json $claims .roles.admin eq json=true;
```

### Issue 4: Regular Expression Match Not Working

**Symptom**: `match` operator does not match as expected

**Cause**: PCRE regular expression syntax error or insufficient escaping

**Solution**:
1. In nginx configuration files, escape `\` as `\\`:
```nginx
# BAD
auth_gate_json $claims .email match "^.*@example\.com$";

# OK
auth_gate_json $claims .email match "^.*@example\\.com$";
```

2. Use `\z` instead of `$` as end-of-string anchor:

nginx's configuration parser interprets `$` as a variable prefix, so it cannot be used directly as a regex end-of-string anchor. Use PCRE's `\z` (end-of-string anchor) instead:
```nginx
# BAD: $ is interpreted as a variable prefix by nginx
auth_gate $var match "^admin$";

# OK: \z is PCRE's end-of-string anchor
auth_gate $var match "^admin\\z";
```

### Issue 5: Input Data Too Large (403 Returned)

**Symptom**: `auth_gate_json` / `auth_gate_jwt` returns 403 with large JSON or JWT tokens

**Cause**: Module input size limits exceeded

**Limits**:
- JSON parse size limit: 1 MiB (input data for `auth_gate_json` / `auth_gate_jwt`)
- JWT token size limit: 16 KiB (token length for `auth_gate_jwt`)

**Solution**:
1. Check input data size and keep it within limits
2. If the JWT is large, minimize the claims included in the token on the IdP side
3. Check for `WARN` level size exceedance messages in debug logs:
```bash
grep 'auth_gate' /var/log/nginx/error.log
```

See the "DoS Defense Mechanisms" section in [SECURITY.md](SECURITY.md) for the complete list of limits.

### Issue 6: JWKS Parse Error (auth_gate_jwt_verify)

**Symptom**: JWKS parsing fails with `auth_gate_jwt_verify`, returning an error code (default 401)

**Error log**:
```
auth_gate_jwt_verify: JWKS response has Content-Encoding 'gzip' for '/jwks';
add 'proxy_set_header Accept-Encoding ""' to the JWKS subrequest location
```
or:
```
auth_gate_jwks: failed to parse JWKS JSON
auth_gate_jwt_verify: JWKS parse failed for '/jwks'
```

**Cause**: The JWKS endpoint returns a compressed response (gzip / br / zstd, etc.). The body fetched via `NGX_HTTP_SUBREQUEST_IN_MEMORY` remains compressed binary and cannot be parsed as JSON

**Solution**:

Add `proxy_set_header Accept-Encoding ""` to the JWKS subrequest location to request an uncompressed response from the upstream:

```nginx
location /jwks {
    internal;
    proxy_set_header Accept-Encoding "";
    proxy_pass https://idp.example.com/.well-known/jwks.json;
}
```

> **Note**: Many IdP JWKS endpoints, including Google (`https://www.googleapis.com/oauth2/v3/certs`), return gzip-compressed responses by default.

## Log Inspection

### Enabling Debug Logs

```nginx
error_log /var/log/nginx/error.log debug;
```

Disable debug logging in production environments (it affects performance).

### Checking Logs

```bash
# Check error logs
tail -f /var/log/nginx/error.log

# Search for auth_gate related logs
grep 'auth_gate' /var/log/nginx/error.log
```

## Configuration Validation Errors

### Validation Command

```bash
nginx -t
```

### Key Validation Errors

**Error 1: `auth_gate: arguments must be variables`**
- **Cause**: `auth_gate` argument does not start with `$`
- **Solution**: Add the `$` prefix to the variable name

**Error 2: `auth_gate: unknown operator "xxx"`**
- **Cause**: An unknown operator was specified
- **Solution**: Use a valid operator (`eq`, `gt`, `ge`, `lt`, `le`, `in`, `any`, `match`, or their negated forms)

**Error 3: `auth_gate_json: field path must start with '.': "xxx"`**
- **Cause**: Field path does not start with `.`
- **Solution**: Add `.` to the beginning of the field path (e.g., `.role`, `.user.name`)

**Error 4: `auth_gate: invalid error code "xxx"`**
- **Cause**: Invalid status code specified for `error=`
- **Solution**: Specify a valid HTTP status code in the 4xx or 5xx range

**Error 5: `auth_gate: arguments must be variables` (when mixing multiple variables with operators)**
- **Cause**: Mixing multiple variables with operators like `auth_gate $var1 $var2 eq "value"`. Since the second argument starts with `$`, it is interpreted as truthiness check mode, and the operator `eq` is not a variable, causing an error
- **Solution**: When using operators, specify only one variable (`auth_gate $var1 eq "value"`)

**Error 6: `auth_gate: unknown operator "match"` (build without PCRE)**
- **Cause**: nginx was built without PCRE support. The `match` / `!match` operators require PCRE
- **Solution**: Rebuild nginx with the `--with-pcre` option. If the `match` operator is not needed, use alternative operators

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Quick start and practical configuration examples
- [INSTALL.md](INSTALL.md): Installation guide (prerequisites, build instructions)
- [SECURITY.md](SECURITY.md): Security considerations (JWT signature verification, input validation)
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial auth_require compatibility
