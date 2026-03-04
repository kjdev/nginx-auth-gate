# Configuration Examples

A collection of configuration examples for the nginx auth_require module. See [DIRECTIVES.md](DIRECTIVES.md) for directive details.

## Quick Start

### Minimal Configuration (Commercial-Compatible)

The following is a minimal configuration example that demonstrates the auth_require module in action (equivalent to the [commercial version sample](https://nginx.org/en/docs/http/ngx_http_auth_require_module.html)):

```nginx
load_module "/usr/lib/nginx/modules/ngx_http_auth_require_module.so";

http {
    # Used in combination with authentication modules such as auth_oidc
    # oidc_provider my_idp { ... }

    map $oidc_claim_role $admin_role {
        "admin"  1;
    }

    server {
        # auth_oidc my_idp;

        location /admin {
            auth_require $admin_role;
            proxy_pass http://backend;
        }
    }
}
```

The basic pattern is to map claim values to variables using the `map` directive and perform truthiness checks with `auth_require`. `$admin_role` becomes `1` only when `role` is `"admin"`, and is empty (falsy) otherwise.

### Minimal Extension Examples

The following are minimal examples of each of this module's extension features:

```nginx
# auth_require comparison mode: compare variable values with operators
auth_require $arg_role eq "admin" error=403;

# auth_require_json: validate fields in a JSON variable
auth_require_json $oidc_claims .role eq "admin" error=403;

# auth_require_jwt: validate JWT token claims (assumes signature verification by another module)
auth_require_jwt $token .sub !eq "" error=401;
```

## Configuration Examples by Use Case

### Variable Truthiness Check (Commercial-Compatible)

```nginx
# Single variable truthiness check
location /member {
    auth_require $oidc_claim_sub error=401;
    proxy_pass http://backend;
}
```

### Variable Operator Comparison

```nginx
# Multiple comparison conditions combined with AND
location /admin-check {
    auth_require $arg_role eq "admin" error=403;
    auth_require $http_x_api_key match "^sk-[a-zA-Z0-9]+$" error=401;
    proxy_pass http://backend;
}
```

### JSON Field Validation

```nginx
# Role and email_verified validation
location /admin {
    auth_require_json $oidc_claims .role eq "admin" error=403;
    auth_require_json $oidc_claims .email_verified eq json=true;
    proxy_pass http://backend;
}

# Nested + array validation
location /api/users {
    auth_require_json $oidc_claims .realm_access.roles
                      any json=["user_manager"] error=403;
    proxy_pass http://backend;
}

# Array element access
location /api/primary-key {
    auth_require_json $oidc_claims .keys[0] eq "primary";
    proxy_pass http://backend;
}

# Regular expression match
location /api/email-check {
    auth_require_json $oidc_claims .email
                      match "^.*@example\\.com$" error=403;
    proxy_pass http://backend;
}
```

### JWT Claim Validation

```nginx
# Direct validation from JWT token (assumes signature verification, see SECURITY.md)
location /external-api {
    set $token $oidc_access_token;
    auth_require_jwt $token .iss eq "https://accounts.example.com";
    auth_require_jwt $token .exp gt json=$auth_require_epoch error=401;
    auth_require_jwt $token .["https://example.com/permissions"]
                     in json=["full","readonly"] error=403;
    proxy_pass http://backend;
}
```

### JWT Required Claims Validation Template

A template covering validation of standard claims defined in RFC 7519. Assumes signature verification has already been performed by authentication modules such as `auth_jwt` or `auth_oidc`.

```nginx
location /api/ {
    # Use a signature-verified token variable (see SECURITY.md)
    set $token $oidc_access_token;

    # iss (Issuer): Validate the token issuer
    auth_require_jwt $token .iss eq "https://accounts.example.com" error=401;

    # sub (Subject): Verify the subject identifier exists
    auth_require_jwt $token .sub !eq "" error=401;

    # aud (Audience): Validate the target audience
    # When aud is a string:
    auth_require_jwt $token .aud eq "https://api.example.com" error=401;
    # When aud is an array (depends on IdP):
    # auth_require_jwt $token .aud any json=["https://api.example.com"] error=401;

    # exp (Expiration Time): Verify the token is not expired
    auth_require_jwt $token .exp gt json=$auth_require_epoch error=401;

    # nbf (Not Before): Verify the token's validity start time has passed
    auth_require_jwt $token .nbf le json=$auth_require_epoch error=401;

    proxy_pass http://backend;
}
```

> **Note**: The `aud` claim can be either a string or a string array depending on the IdP. Choose `eq` (string) or `any` (array) according to your IdP's specification.

### Compound Conditions (Multiple Directives = AND)

```nginx
# Combination of truthiness check and JSON field validation
location /sensitive {
    auth_require $is_admin error=403;
    auth_require_json $oidc_claims .org.plan eq "enterprise";
    proxy_pass http://backend;
}
```

### Comprehensive Configuration Example

```nginx
http {
    # Used in combination with authentication modules such as auth_oidc
    # oidc_provider my_idp { ... }

    map $oidc_claim_role $is_admin {
        "admin"  1;
        default  0;
    }

    server {
        # auth_oidc my_idp;

        # 1. Variable truthiness check (commercial-compatible)
        location /member {
            auth_require $oidc_claim_sub error=401;
            proxy_pass http://backend;
        }

        # 2. Variable comparison mode
        location /admin-check {
            auth_require $arg_role eq "admin" error=403;
            auth_require $http_x_api_key match "^sk-[a-zA-Z0-9]+$" error=401;
            proxy_pass http://backend;
        }

        # 3. JSON field validation
        location /admin {
            auth_require_json $oidc_claims .role eq "admin" error=403;
            auth_require_json $oidc_claims .email_verified eq json=true;
            proxy_pass http://backend;
        }

        # 4. Nested + array validation
        location /api/users {
            auth_require_json $oidc_claims .realm_access.roles
                              any json=["user_manager"] error=403;
            proxy_pass http://backend;
        }

        # 5. Array element access
        location /api/primary-key {
            auth_require_json $oidc_claims .keys[0] eq "primary";
            proxy_pass http://backend;
        }

        # 6. Direct validation from JWT token (assumes signature verification)
        location /external-api {
            set $token $oidc_access_token;
            auth_require_jwt $token .iss eq "https://accounts.example.com";
            auth_require_jwt $token .exp gt json=$auth_require_epoch error=401;
            auth_require_jwt $token .["https://example.com/permissions"]
                             in json=["full","readonly"] error=403;
            proxy_pass http://backend;
        }

        # 7. Regular expression match
        location /api/email-check {
            auth_require_json $oidc_claims .email
                              match "^.*@example\\.com$" error=403;
            proxy_pass http://backend;
        }

        # 8. Compound conditions (multiple directives = AND)
        location /sensitive {
            auth_require $is_admin error=403;
            auth_require_json $oidc_claims .org.plan eq "enterprise";
            proxy_pass http://backend;
        }
    }
}
```

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [INSTALL.md](INSTALL.md): Installation guide (prerequisites, build instructions)
- [SECURITY.md](SECURITY.md): Security considerations (JWT signature verification, input validation)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting (common issues, log inspection)
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial version compatibility
