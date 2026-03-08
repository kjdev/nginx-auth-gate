/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * JWT signature verification (JWS) for auth_gate module
 *
 * Verifies JWT signatures using EVP_PKEY objects from a parsed JWKS keyset.
 * Supports RSA (RS/PS), ECDSA (ES), and EdDSA algorithms.
 *
 * Based on ngx_oidc_jwt.c signature verification from the OIDC module.
 */

#ifndef _NGX_AUTH_GATE_JWS_H_INCLUDED_
#define _NGX_AUTH_GATE_JWS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_auth_gate_jwks.h"

/**
 * Verify JWT signature against a JWKS keyset
 *
 * Decodes the JWT header to extract alg and kid, finds a matching
 * key in the keyset, and verifies the signature using OpenSSL EVP API.
 *
 * @param[in] token   JWT token string (header.payload.signature)
 * @param[in] keyset  Parsed JWKS keyset
 * @param[in] pool    nginx memory pool for temporary allocations
 * @param[in] log     nginx log for error/debug output
 *
 * @return NGX_OK if signature is valid,
 *         NGX_DECLINED if signature is invalid,
 *         NGX_ERROR on internal error
 */
ngx_int_t ngx_auth_gate_jws_verify(ngx_str_t *token,
    ngx_auth_gate_jwks_keyset_t *keyset, ngx_pool_t *pool, ngx_log_t *log);

#endif /* _NGX_AUTH_GATE_JWS_H_INCLUDED_ */
