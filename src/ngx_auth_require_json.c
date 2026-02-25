/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * JSON abstraction layer with Jansson implementation
 *
 * This module provides a thin wrapper around the Jansson JSON library,
 * abstracting the underlying JSON implementation from module logic.
 * Based on ngx_oidc_json.c from the OIDC module.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_auth_require_json.h"
#include <jansson.h>
#include <math.h>

/* Internal cast macro for Jansson implementation */
#define JSON_CAST(json) ((json_t *) (json))


ngx_auth_require_json_t *
ngx_auth_require_json_parse(ngx_str_t *data)
{
    json_t *root;
    json_error_t error;

    if (data == NULL || data->data == NULL || data->len == 0) {
        return NULL;
    }

    if (data->len > NGX_AUTH_REQUIRE_MAX_JSON_SIZE) {
        return NULL;
    }

    /*
     * JSON_DECODE_ANY: accept scalars for expected-value comparisons.
     * JSON_REJECT_DUPLICATES: reject duplicate keys.
     * Error details are not propagated (opaque wrapper boundary).
     */
    root = json_loadb((const char *) data->data, data->len,
                      JSON_DECODE_ANY | JSON_REJECT_DUPLICATES, &error);
    if (root == NULL) {
        return NULL;
    }

    return (ngx_auth_require_json_t *) root;
}


void
ngx_auth_require_json_free(ngx_auth_require_json_t *json)
{
    if (json) {
        json_decref(JSON_CAST(json));
    }
}


ngx_auth_require_json_type_t
ngx_auth_require_json_type(ngx_auth_require_json_t *json)
{
    json_t *j = JSON_CAST(json);

    if (j == NULL) {
        return NGX_AUTH_REQUIRE_JSON_INVALID;
    }

    switch (json_typeof(j)) {

    case JSON_NULL:
        return NGX_AUTH_REQUIRE_JSON_NULL;

    case JSON_TRUE:
    case JSON_FALSE:
        return NGX_AUTH_REQUIRE_JSON_BOOLEAN;

    case JSON_INTEGER:
        return NGX_AUTH_REQUIRE_JSON_INTEGER;

    case JSON_REAL:
        return NGX_AUTH_REQUIRE_JSON_REAL;

    case JSON_STRING:
        return NGX_AUTH_REQUIRE_JSON_STRING;

    case JSON_ARRAY:
        return NGX_AUTH_REQUIRE_JSON_ARRAY;

    case JSON_OBJECT:
        return NGX_AUTH_REQUIRE_JSON_OBJECT;

    default:
        return NGX_AUTH_REQUIRE_JSON_INVALID;
    }
}


ngx_auth_require_json_t *
ngx_auth_require_json_object_get(ngx_auth_require_json_t *json, ngx_str_t *key)
{
    json_t *obj = JSON_CAST(json);

    if (obj == NULL || !json_is_object(obj) || key == NULL) {
        return NULL;
    }

    return (ngx_auth_require_json_t *) json_object_getn(
        obj, (const char *) key->data, key->len);
}


size_t
ngx_auth_require_json_array_size(ngx_auth_require_json_t *json)
{
    json_t *arr = JSON_CAST(json);

    if (arr == NULL || !json_is_array(arr)) {
        return 0;
    }

    return json_array_size(arr);
}


ngx_auth_require_json_t *
ngx_auth_require_json_array_get(ngx_auth_require_json_t *json, size_t index)
{
    json_t *arr = JSON_CAST(json);

    if (arr == NULL || !json_is_array(arr)) {
        return NULL;
    }

    return (ngx_auth_require_json_t *) json_array_get(arr, index);
}


ngx_int_t
ngx_auth_require_json_string(ngx_auth_require_json_t *json, ngx_str_t *value)
{
    json_t *j = JSON_CAST(json);
    const char *str;

    if (j == NULL || !json_is_string(j)) {
        return NGX_ERROR;
    }

    str = json_string_value(j);
    if (str == NULL) {
        return NGX_ERROR;
    }

    value->data = (u_char *) str;
    value->len = json_string_length(j);

    return NGX_OK;
}


ngx_int_t
ngx_auth_require_json_integer(ngx_auth_require_json_t *json, int64_t *value)
{
    json_t *j = JSON_CAST(json);

    if (j == NULL || !json_is_integer(j)) {
        return NGX_ERROR;
    }

    *value = (int64_t) json_integer_value(j);

    return NGX_OK;
}


ngx_int_t
ngx_auth_require_json_real(ngx_auth_require_json_t *json, double *value)
{
    json_t *j = JSON_CAST(json);

    if (j == NULL || !json_is_real(j)) {
        return NGX_ERROR;
    }

    *value = json_real_value(j);

    return NGX_OK;
}


ngx_int_t
ngx_auth_require_json_boolean(ngx_auth_require_json_t *json, ngx_flag_t *value)
{
    json_t *j = JSON_CAST(json);

    if (j == NULL || (!json_is_true(j) && !json_is_false(j))) {
        return NGX_ERROR;
    }

    *value = json_is_true(j) ? 1 : 0;

    return NGX_OK;
}


ngx_auth_require_json_t *
ngx_auth_require_json_from_string(ngx_str_t *str)
{
    json_t *j;

    if (str == NULL || str->data == NULL
        || str->len > NGX_AUTH_REQUIRE_MAX_JSON_SIZE)
    {
        return NULL;
    }

    /*
     * json_stringn() is binary-safe: it stores exactly str->len bytes,
     * including any embedded NUL bytes.  This is intentional—the match
     * operator's NUL byte check on the subject side catches injection
     * attempts before PCRE sees the string.
     */
    j = json_stringn((const char *) str->data, str->len);

    return (ngx_auth_require_json_t *) j;
}


ngx_flag_t
ngx_auth_require_json_equal(ngx_auth_require_json_t *a,
    ngx_auth_require_json_t *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }

    /*
     * Jansson's json_equal() has unbounded recursion depth.
     * MAX_JSON_SIZE constrains nesting; see SECURITY.ja.md for analysis.
     */
    return json_equal(JSON_CAST(a), JSON_CAST(b)) ? 1 : 0;
}


ngx_int_t
ngx_auth_require_json_number(ngx_auth_require_json_t *json, double *value)
{
    json_t *j = JSON_CAST(json);

    if (j == NULL) {
        return NGX_ERROR;
    }

    if (json_is_integer(j)) {
        *value = (double) json_integer_value(j);
        return NGX_OK;
    }

    if (json_is_real(j)) {
        *value = json_real_value(j);
        return NGX_OK;
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_auth_require_json_compare(ngx_auth_require_json_t *a,
    ngx_auth_require_json_t *b, double *diff, ngx_log_t *log)
{
    int64_t ia, ib;
    double da, db;

    if (a == NULL || b == NULL || diff == NULL) {
        return NGX_ERROR;
    }

    /* both integers: compare directly with int64_t precision */
    if (ngx_auth_require_json_integer(a, &ia) == NGX_OK
        && ngx_auth_require_json_integer(b, &ib) == NGX_OK)
    {
        *diff = (ia > ib) ? 1.0 : (ia < ib) ? -1.0 : 0.0;
        return NGX_OK;
    }

    /* mixed integer/real: promote real to int64_t if lossless */
    if (ngx_auth_require_json_integer(a, &ia) == NGX_OK
        && ngx_auth_require_json_real(b, &db) == NGX_OK)
    {
        /* strict < for INT64_MAX: (double) INT64_MAX rounds up to 2^63 */
        if (db >= (double) INT64_MIN && db < (double) INT64_MAX
            && db == (double) (int64_t) db)
        {
            ib = (int64_t) db;
            *diff = (ia > ib) ? 1.0 : (ia < ib) ? -1.0 : 0.0;
            return NGX_OK;
        }
    }

    if (ngx_auth_require_json_real(a, &da) == NGX_OK
        && ngx_auth_require_json_integer(b, &ib) == NGX_OK)
    {
        if (da >= (double) INT64_MIN && da < (double) INT64_MAX
            && da == (double) (int64_t) da)
        {
            ia = (int64_t) da;
            *diff = (ia > ib) ? 1.0 : (ia < ib) ? -1.0 : 0.0;
            return NGX_OK;
        }
    }

    /* fall back to double comparison */
    if (ngx_auth_require_json_number(a, &da) != NGX_OK
        || ngx_auth_require_json_number(b, &db) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (isnan(da) || isnan(db) || isinf(da) || isinf(db)) {
        return NGX_ERROR;
    }

    if (log != NULL) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "auth_require: numeric comparison using double "
                       "fallback (possible precision loss for integers "
                       "> 2^53): %f vs %f", da, db);
    }

    *diff = (da > db) ? 1.0 : (da < db) ? -1.0 : 0.0;

    return NGX_OK;
}
