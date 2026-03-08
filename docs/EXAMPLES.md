# Configuration Examples

A collection of configuration examples for the nginx auth_gate module. See [DIRECTIVES.md](DIRECTIVES.md) for directive details.

## Quick Start

### Minimal Configuration

The following are minimal examples of each directive provided by the auth_gate module:

```nginx
load_module "/usr/lib/nginx/modules/ngx_http_auth_gate_module.so";

http {
    server {
        # auth_gate: compare variable values with operators
        location /admin {
            auth_gate $arg_role eq "admin" error=403;
            proxy_pass http://backend;
        }

        # auth_gate_json: validate fields in a JSON variable
        location /api {
            auth_gate_json $json .role eq "admin" error=403;
            proxy_pass http://backend;
        }

        # auth_gate_jwt: validate JWT token claims (assumes signature verification by another module)
        location /external {
            auth_gate_jwt $token .sub !eq "" error=401;
            proxy_pass http://backend;
        }
    }
}
```

## Configuration Examples by Use Case

### Variable Operator Comparison

```nginx
# Multiple comparison conditions combined with AND
location /admin-check {
    auth_gate $arg_role eq "admin" error=403;
    auth_gate $http_x_api_key match "^sk-[a-zA-Z0-9]+$" error=401;
    proxy_pass http://backend;
}
```

### JSON Field Validation

```nginx
# Role and email_verified validation
location /admin {
    auth_gate_json $oidc_claims .role eq "admin" error=403;
    auth_gate_json $oidc_claims .email_verified eq json=true;
    proxy_pass http://backend;
}

# Nested + array validation
location /api/users {
    auth_gate_json $oidc_claims .realm_access.roles
                      any json=["user_manager"] error=403;
    proxy_pass http://backend;
}

# Array element access
location /api/primary-key {
    auth_gate_json $oidc_claims .keys[0] eq "primary";
    proxy_pass http://backend;
}

# Regular expression match
location /api/email-check {
    auth_gate_json $oidc_claims .email
                      match "^.*@example\\.com$" error=403;
    proxy_pass http://backend;
}
```

### JWT Signature Verification + Claim Validation

```nginx
# Strip "Bearer " prefix from Authorization header
map $http_authorization $bearer_token {
    default "";
    ~*^Bearer\s+(?<t>.+)$ $t;
}

# Verify JWT signature using JWKS, then validate claims
location = /jwks {
    internal;
    proxy_set_header Accept-Encoding "";
    proxy_pass https://idp.example.com/.well-known/jwks.json;
}

location /api {
    set $token $bearer_token;

    # Step 1: Verify signature
    auth_gate_jwt_verify $token jwks=/jwks;

    # Step 2: Validate claims
    auth_gate_jwt $token .iss eq "https://accounts.example.com";
    auth_gate_jwt $token .exp gt json=$auth_gate_epoch error=401;
    auth_gate_jwt $token .role eq "admin" error=403;
    proxy_pass http://backend;
}
```

> **Note**: The `Authorization` header typically contains a `"Bearer "` prefix (e.g., `Bearer eyJ...`). Use `map` to strip the prefix before passing to `auth_gate_jwt_verify`. If the token is stored in a cookie or a custom header without a prefix, you can use it directly.

### JWT Claim Validation (External Signature Verification)

```nginx
# Direct validation from JWT token (assumes signature verification by another module)
location /external-api {
    set $token $oidc_access_token;
    auth_gate_jwt $token .iss eq "https://accounts.example.com";
    auth_gate_jwt $token .exp gt json=$auth_gate_epoch error=401;
    auth_gate_jwt $token .["https://example.com/permissions"]
                     in json=["full","readonly"] error=403;
    proxy_pass http://backend;
}
```

### JWT Required Claims Validation Template

A template covering validation of standard claims defined in RFC 7519. Signature verification can be performed using `auth_gate_jwt_verify` or delegated to authentication modules such as `auth_jwt` or `oidc`.

```nginx
location /api/ {
    # Option A: Verify signature with auth_gate_jwt_verify
    # auth_gate_jwt_verify $token jwks=/jwks;
    # Option B: Use a signature-verified token variable from another module
    set $token $oidc_access_token;

    # iss (Issuer): Validate the token issuer
    auth_gate_jwt $token .iss eq "https://accounts.example.com" error=401;

    # sub (Subject): Verify the subject identifier exists
    auth_gate_jwt $token .sub !eq "" error=401;

    # aud (Audience): Validate the target audience
    # When aud is a string:
    auth_gate_jwt $token .aud eq "https://api.example.com" error=401;
    # When aud is an array (depends on IdP):
    # auth_gate_jwt $token .aud any json=["https://api.example.com"] error=401;

    # exp (Expiration Time): Verify the token is not expired
    auth_gate_jwt $token .exp gt json=$auth_gate_epoch error=401;

    # nbf (Not Before): Verify the token's validity start time has passed
    auth_gate_jwt $token .nbf le json=$auth_gate_epoch error=401;

    proxy_pass http://backend;
}
```

> **Note**: The `aud` claim can be either a string or a string array depending on the IdP. Choose `eq` (string) or `any` (array) according to your IdP's specification.

### Variable Truthiness Check

```nginx
# Single variable truthiness check (equivalent to the commercial auth_require behavior)
location /member {
    auth_gate $oidc_claim_sub error=401;
    proxy_pass http://backend;
}
```

### Compound Conditions (Multiple Directives = AND)

```nginx
# Combination of truthiness check and JSON field validation
location /sensitive {
    auth_gate $is_admin error=403;
    auth_gate_json $oidc_claims .org.plan eq "enterprise";
    proxy_pass http://backend;
}
```

### Comprehensive Configuration Example

```nginx
http {
    # Used in combination with authentication modules such as oidc
    # oidc_provider my_idp { ... }

    map $http_authorization $bearer_token {
        default "";
        ~*^Bearer\s+(?<t>.+)$ $t;
    }

    map $oidc_claim_role $is_admin {
        "admin"  1;
        default  0;
    }

    server {
        # auth_oidc my_idp;

        # 1. Variable comparison mode
        location /admin-check {
            auth_gate $arg_role eq "admin" error=403;
            auth_gate $http_x_api_key match "^sk-[a-zA-Z0-9]+$" error=401;
            proxy_pass http://backend;
        }

        # 2. JSON field validation
        location /admin {
            auth_gate_json $oidc_claims .role eq "admin" error=403;
            auth_gate_json $oidc_claims .email_verified eq json=true;
            proxy_pass http://backend;
        }

        # 3. Nested + array validation
        location /api/users {
            auth_gate_json $oidc_claims .realm_access.roles
                              any json=["user_manager"] error=403;
            proxy_pass http://backend;
        }

        # 4. Array element access
        location /api/primary-key {
            auth_gate_json $oidc_claims .keys[0] eq "primary";
            proxy_pass http://backend;
        }

        # 5. JWT signature verification + claim validation
        location = /jwks {
            internal;
            proxy_set_header Accept-Encoding "";
            proxy_pass https://idp.example.com/.well-known/jwks.json;
        }
        location /external-api {
            set $token $bearer_token;
            auth_gate_jwt_verify $token jwks=/jwks;
            auth_gate_jwt $token .iss eq "https://accounts.example.com";
            auth_gate_jwt $token .exp gt json=$auth_gate_epoch error=401;
            auth_gate_jwt $token .["https://example.com/permissions"]
                             in json=["full","readonly"] error=403;
            proxy_pass http://backend;
        }

        # 6. Regular expression match
        location /api/email-check {
            auth_gate_json $oidc_claims .email
                              match "^.*@example\\.com$" error=403;
            proxy_pass http://backend;
        }

        # 7. Variable truthiness check
        location /member {
            auth_gate $oidc_claim_sub error=401;
            proxy_pass http://backend;
        }

        # 8. Compound conditions (multiple directives = AND)
        location /sensitive {
            auth_gate $is_admin error=403;
            auth_gate_json $oidc_claims .org.plan eq "enterprise";
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
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial auth_require compatibility
