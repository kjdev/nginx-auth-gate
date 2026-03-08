# Installation

Instructions for installing the nginx auth_gate module.

## Prerequisites

### Required Libraries

- **nginx**: 1.18.0 or later
- **jansson**: 2.14 or later (for JSON processing; uses APIs such as `json_string_length()`)
- **OpenSSL**: 3.0 or later (for JWT signature verification with `auth_gate_jwt_verify`)

### Optional Libraries

- **PCRE**: 8.x or later (for regular expression processing). Required when using `match` / `!match` operators. The module itself works without PCRE, but the `match` operator becomes unavailable

### Package Installation Examples

**Debian/Ubuntu**:
```bash
apt-get install -y \
    build-essential \
    libpcre3-dev \
    zlib1g-dev \
    libjansson-dev \
    libssl-dev
# libpcre3-dev is only needed when using the match operator (optional)
```

**RHEL/CentOS/Fedora**:
```bash
dnf install -y \
    gcc \
    make \
    pcre-devel \
    zlib-devel \
    jansson-devel \
    openssl-devel
# pcre-devel is only needed when using the match operator (optional)
```

**Alpine Linux**:
```bash
apk add \
    gcc \
    make \
    musl-dev \
    pcre-dev \
    zlib-dev \
    jansson-dev \
    openssl-dev
# pcre-dev is only needed when using the match operator (optional)
```

## Building from Source

### Step 1: Obtain nginx Source Code

```bash
# Download the nginx source code (adjust the version as needed)
wget http://nginx.org/download/nginx-x.y.z.tar.gz
tar -xzf nginx-x.y.z.tar.gz
cd nginx-x.y.z
```

### Step 2: Run configure

```bash
./configure \
    --with-compat \
    --with-pcre \
    --add-dynamic-module=..
```

**Options**:
- `--with-compat`: Enable dynamic module compatibility
- `--with-pcre`: PCRE regular expression support (required for `match` operator). The module itself works without this option, but `match` / `!match` operators become unavailable
- `--add-dynamic-module`: Build auth_gate module as a dynamic module

### Step 3: Build

```bash
make
```

### Step 4: Verify the Module

Upon successful build, the dynamic module will be generated:

```bash
ls -l objs/ngx_http_auth_gate_module.so
```

### Step 5: Load the Module

Add the following to the top level of the nginx configuration file (typically `/etc/nginx/nginx.conf`):

```nginx
load_module "/path/to/objs/ngx_http_auth_gate_module.so";
```

### Step 6: Validate Configuration and Start

```bash
# Validate configuration
nginx -t

# Start nginx
nginx
```

**Note**:
- This guide covers basic build instructions only
- For system installation (`make install`), please follow the appropriate procedure for your environment

## Docker

You can build nginx with the module using a Docker image.

```bash
# Build the Docker image
docker build -t nginx-auth-gate .

# Start the container
docker run -d -p 80:80 \
    -v /path/to/default.conf:/etc/nginx/conf.d/default.conf:ro \
    nginx-auth-gate
```

The Dockerfile is pre-configured to automatically load the module.

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Quick start and practical configuration examples
- [SECURITY.md](SECURITY.md): Security considerations (JWT signature verification, input validation)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting (common issues, log inspection)
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial auth_require compatibility
