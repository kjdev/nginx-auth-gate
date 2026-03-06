# Commercial Version Compatibility

Describes the compatibility between the nginx auth_gate module and the [`auth_require` directive from the nginx commercial subscription](https://nginx.org/en/docs/http/ngx_http_auth_require_module.html).

## Overview

The truthiness check mode (without operator) of the `auth_gate` directive behaves equivalently to the `auth_require` directive from the nginx commercial subscription. The syntax and behavior for basic truthiness checks — verifying that a variable is not an empty string and not `"0"` — are identical.

```nginx
# auth_gate truthiness check mode (equivalent to commercial auth_require)
auth_gate $oidc_claim_sub error=401;
auth_gate $is_admin $has_permission error=403;
```

The auth_gate module additionally provides operator-based comparison mode (`auth_gate $var <op> <expected>`), JSON field validation (`auth_gate_json`), and JWT claim validation (`auth_gate_jwt`).

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Quick start and practical configuration examples
- [INSTALL.md](INSTALL.md): Installation guide (prerequisites, build instructions)
- [SECURITY.md](SECURITY.md): Security considerations (JWT signature verification, input validation)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting (common issues, log inspection)
