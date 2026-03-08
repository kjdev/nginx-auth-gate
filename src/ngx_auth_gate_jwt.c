/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * JWT payload decoding for auth_gate module
 *
 * Extracts and decodes the JWT payload segment (base64url).
 * No signature verification is performed — authentication is
 * delegated to auth_jwt or oidc modules.
 *
 * Based on ngx_oidc_jwt_decode_payload() from the OIDC module.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_auth_gate_jwt.h"


static ngx_int_t
jwt_find_payload(ngx_str_t *token, ngx_str_t *payload_b64)
{
    u_char *start, *end;

    /*
     * Extract payload from compact JWT: header.payload.signature
     * Enforces exactly 3 segments with non-empty header and payload.
     */

    start = ngx_strlchr(token->data, token->data + token->len, '.');
    if (start == NULL) {
        return NGX_ERROR;
    }

    /* Reject empty header segment (e.g. ".payload.sig") */
    if (start == token->data) {
        return NGX_ERROR;
    }

    start++;

    end = ngx_strlchr(start, token->data + token->len, '.');
    if (end == NULL) {
        return NGX_ERROR;
    }

    /* Reject extra segments (e.g. JWE 5-segment tokens) */
    if (ngx_strlchr(end + 1, token->data + token->len, '.') != NULL) {
        return NGX_ERROR;
    }

    payload_b64->data = start;
    payload_b64->len = end - start;

    if (payload_b64->len == 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_auth_gate_json_t *
ngx_auth_gate_jwt_decode_payload(ngx_str_t *token, ngx_pool_t *pool)
{
    u_char *decoded;
    ngx_str_t payload_b64, payload;
    size_t decoded_len;
    ngx_auth_gate_json_t *json;

    if (token == NULL || token->data == NULL || token->len == 0
        || pool == NULL)
    {
        return NULL;
    }

    if (token->len > NGX_AUTH_GATE_MAX_JWT_LENGTH) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "auth_gate_jwt: token too large: %uz",
                      token->len);
        return NULL;
    }

    /* Find the payload segment between dots */
    if (jwt_find_payload(token, &payload_b64) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "auth_gate_jwt: invalid JWT format");
        return NULL;
    }

    decoded_len = ngx_base64_decoded_length(payload_b64.len);
    decoded = ngx_pnalloc(pool, decoded_len + 1);
    if (decoded == NULL) {
        return NULL;
    }

    payload.data = decoded;

    if (ngx_decode_base64url(&payload, &payload_b64) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "auth_gate_jwt: base64url decode failed");
        ngx_memzero(decoded, decoded_len + 1);
        return NULL;
    }

    payload.data[payload.len] = '\0';

    json = ngx_auth_gate_json_parse(&payload);

    /*
     * Clear decoded payload to minimize sensitive data residency in memory.
     *
     * Note: Jansson's json_loads() makes internal copies of string values,
     * so those copies remain in heap memory until json_decref() is called.
     * This clearing only covers the base64-decoded buffer we allocated.
     */
    ngx_memzero(decoded, decoded_len + 1);

    if (json == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "auth_gate_jwt: payload JSON parse failed");
        return NULL;
    }

    return json;
}


ngx_auth_gate_json_t *
ngx_auth_gate_jwt_decode_header(ngx_str_t *header_b64, ngx_pool_t *pool)
{
    u_char *decoded;
    ngx_str_t header;
    size_t decoded_len;
    ngx_auth_gate_json_t *json;

    if (header_b64 == NULL || header_b64->data == NULL
        || header_b64->len == 0 || pool == NULL)
    {
        return NULL;
    }

    if (header_b64->len > NGX_AUTH_GATE_MAX_JWT_HEADER_LENGTH) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "auth_gate_jwt: header segment too large: %uz",
                      header_b64->len);
        return NULL;
    }

    decoded_len = ngx_base64_decoded_length(header_b64->len);
    decoded = ngx_pnalloc(pool, decoded_len + 1);
    if (decoded == NULL) {
        return NULL;
    }

    header.data = decoded;

    if (ngx_decode_base64url(&header, header_b64) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "auth_gate_jwt: header base64url decode failed");
        ngx_memzero(decoded, decoded_len + 1);
        return NULL;
    }

    header.data[header.len] = '\0';

    json = ngx_auth_gate_json_parse(&header);

    ngx_memzero(decoded, decoded_len + 1);

    if (json == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "auth_gate_jwt: header JSON parse failed");
        return NULL;
    }

    return json;
}
