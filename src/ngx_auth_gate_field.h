/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_AUTH_GATE_FIELD_H_INCLUDED_
#define _NGX_AUTH_GATE_FIELD_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "nxe_json.h"

/** Field segment type */
typedef enum {
    NGX_AUTH_GATE_FIELD_KEY = 0,   /* object key */
    NGX_AUTH_GATE_FIELD_INDEX      /* array index */
} ngx_auth_gate_field_type_t;

/** Single segment of a field path */
typedef struct {
    ngx_auth_gate_field_type_t  type;
    ngx_str_t                   key;        /* key name (KEY type) */
    size_t                      index;      /* array index (INDEX type) */
} ngx_auth_gate_field_segment_t;

/** Parsed field path */
typedef struct {
    ngx_array_t *segments;     /* ngx_auth_gate_field_segment_t array */
} ngx_auth_gate_field_path_t;

/*
 * Empty segments array means "root" (the "." path).
 *
 * ".role"         -> [{KEY, "role"}]
 * ".user.role"    -> [{KEY, "user"}, {KEY, "role"}]
 * ".keys[0]"      -> [{KEY, "keys"}, {INDEX, 0}]
 * ".[0]"          -> [{INDEX, 0}]
 * '.["a.b"]'      -> [{KEY, "a.b"}]
 * ".users[0].name" -> [{KEY, "users"}, {INDEX, 0}, {KEY, "name"}]
 */

/**
 * Parse a JQ-like field path (called at config parse time)
 *
 * @param[in]  pool  memory pool for allocation
 * @param[in]  raw   raw field path string (e.g., ".user.role")
 * @param[out] path  parsed field path
 *
 * @return NGX_OK on success, NGX_ERROR on parse error
 */
ngx_int_t ngx_auth_gate_field_parse(ngx_pool_t *pool,
    ngx_str_t *raw, ngx_auth_gate_field_path_t *path);

/**
 * Extract a field value from a JSON tree (called at request time)
 *
 * Returns root if segments array is empty (root path).
 *
 * @param[in] root  JSON root object
 * @param[in] path  parsed field path
 *
 * @return JSON value at the path, or NULL if not found
 */
nxe_json_t *ngx_auth_gate_field_get(
    nxe_json_t *root,
    ngx_auth_gate_field_path_t *path);

/**
 * Reconstruct field path string from parsed segments (for log messages)
 *
 * @param[in] field  parsed field path
 * @param[in] pool   memory pool for allocation
 *
 * @return reconstructed path string, or {0, NULL} on allocation failure
 */
ngx_str_t ngx_auth_gate_field_path_str(ngx_auth_gate_field_path_t *field,
    ngx_pool_t *pool);

#endif /* _NGX_AUTH_GATE_FIELD_H_INCLUDED_ */
