/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_AUTH_GATE_JWT_H_INCLUDED_
#define _NGX_AUTH_GATE_JWT_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "nxe_json.h"

/** Maximum JWT token length (16 KiB) */
#define NGX_AUTH_GATE_MAX_JWT_LENGTH  16384

/** Maximum JWT header segment length (8 KiB, base64url-encoded) */
#define NGX_AUTH_GATE_MAX_JWT_HEADER_LENGTH  8192

/**
 * Decode JWT payload
 *
 * Extracts and Base64url-decodes the JWT payload (second segment),
 * then parses it as JSON. No signature verification is performed.
 *
 * @param[in] token  JWT token string (header.payload.signature)
 * @param[in] pool   nginx memory pool for buffer allocation
 *
 * @return Parsed JSON object (caller must call nxe_json_free()),
 *         or NULL on failure
 */
nxe_json_t *ngx_auth_gate_jwt_decode_payload(
    ngx_str_t *token, ngx_pool_t *pool);

/**
 * Decode JWT header
 *
 * Extracts and Base64url-decodes the JWT header (first segment),
 * then parses it as JSON. Used by signature verification to extract
 * alg and kid fields.
 *
 * @param[in] header_b64  Base64url-encoded header segment (before first dot)
 * @param[in] pool        nginx memory pool for buffer allocation
 *
 * @return Parsed JSON object (caller must call nxe_json_free()),
 *         or NULL on failure
 */
nxe_json_t *ngx_auth_gate_jwt_decode_header(
    ngx_str_t *header_b64, ngx_pool_t *pool);

#endif /* _NGX_AUTH_GATE_JWT_H_INCLUDED_ */
