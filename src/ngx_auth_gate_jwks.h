/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * JWKS (JSON Web Key Set) parser for auth_gate module
 *
 * Parses JWKS JSON and converts JWK entries to OpenSSL EVP_PKEY objects.
 * Supports RSA, EC (P-256/P-384/P-521/secp256k1), and OKP (Ed25519/Ed448).
 *
 * Based on ngx_oidc_jwks.c from the OIDC module (simplified, no SHM cache).
 */

#ifndef _NGX_AUTH_GATE_JWKS_H_INCLUDED_
#define _NGX_AUTH_GATE_JWKS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>

/** Maximum JWKS JSON size (256 KiB) */
#define NGX_AUTH_GATE_MAX_JWKS_SIZE  262144

/** Maximum number of keys in JWKS */
#define NGX_AUTH_GATE_MAX_JWKS_KEYS  64

/** JWK key types */
typedef enum {
    NGX_AUTH_GATE_JWK_UNKNOWN = 0,
    NGX_AUTH_GATE_JWK_RSA,
    NGX_AUTH_GATE_JWK_EC,
    NGX_AUTH_GATE_JWK_OKP
} ngx_auth_gate_jwk_type_t;

/** Single JWK key entry */
typedef struct {
    ngx_str_t                 kid;
    ngx_str_t                 alg;
    ngx_str_t                 crv;  /* EC curve name (P-256, P-384, P-521, secp256k1) */
    ngx_auth_gate_jwk_type_t  kty;
    EVP_PKEY                 *pkey;
} ngx_auth_gate_jwks_key_t;

/** Parsed JWKS keyset */
typedef struct {
    ngx_array_t *keys;                  /* ngx_auth_gate_jwks_key_t */
} ngx_auth_gate_jwks_keyset_t;

/**
 * Parse JWKS JSON and build keyset
 *
 * Parses the JWKS JSON string, extracts JWK entries, and converts
 * each supported key to an EVP_PKEY. A pool cleanup handler is
 * registered to free EVP_PKEY resources when the pool is destroyed.
 *
 * Keys with "use": "enc" are skipped (only "sig" or unspecified are used).
 *
 * @param[in] pool  nginx memory pool for allocation and cleanup
 * @param[in] json  JWKS JSON string
 * @param[in] log   nginx log for error/debug output
 *
 * @return Parsed keyset, or NULL on failure
 */
ngx_auth_gate_jwks_keyset_t *ngx_auth_gate_jwks_parse(
    ngx_pool_t *pool, ngx_str_t *json, ngx_log_t *log);

#endif /* _NGX_AUTH_GATE_JWKS_H_INCLUDED_ */
