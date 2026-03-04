# Commercial Version Compatibility

Describes the compatibility between the nginx auth_require module and the [`auth_require` directive from the nginx commercial subscription](https://nginx.org/en/docs/http/ngx_http_auth_require_module.html).

## Overview

This module is an OSS implementation of the `auth_require` directive from the nginx commercial subscription.

**Commercial-compatible**: The truthiness check mode of the `auth_require` directive is compatible with the commercial version.

**Extensions**: The following features are provided as proprietary extensions not available in the commercial version:
- Operator comparison mode for `auth_require`
- `auth_require_json` directive (JSON field validation)
- `auth_require_jwt` directive (JWT claim validation)

## Directive Comparison

| Commercial Version | OSS Version (This Module) | Compatibility |
|-------------------|--------------------------|---------------|
| `auth_require $var [error=...]` | `auth_require $var [error=...]` | Fully compatible |
| — | `auth_require $var <op> <expected> [error=...]` | Proprietary extension |
| — | `auth_require_json $var <field> <op> <expected> [error=...]` | Proprietary extension |
| — | `auth_require_jwt $var <claim> <op> <expected> [error=...]` | Proprietary extension |

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Quick start and practical configuration examples
- [INSTALL.md](INSTALL.md): Installation guide (prerequisites, build instructions)
- [SECURITY.md](SECURITY.md): Security considerations (JWT signature verification, input validation)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting (common issues, log inspection)
