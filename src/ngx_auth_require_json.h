/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_AUTH_REQUIRE_JSON_H_INCLUDED_
#define _NGX_AUTH_REQUIRE_JSON_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/**
 * Opaque JSON value handle
 *
 * Hides Jansson's json_t* from consumers so the underlying
 * implementation can change without affecting callers.
 */
typedef void ngx_auth_require_json_t;

/**
 * JSON value type enumeration
 *
 * Maps to Jansson's json_type enum but provides an abstraction layer.
 */
typedef enum {
    NGX_AUTH_REQUIRE_JSON_INVALID = -1,
    NGX_AUTH_REQUIRE_JSON_NULL,
    NGX_AUTH_REQUIRE_JSON_BOOLEAN,
    NGX_AUTH_REQUIRE_JSON_INTEGER,
    NGX_AUTH_REQUIRE_JSON_REAL,
    NGX_AUTH_REQUIRE_JSON_STRING,
    NGX_AUTH_REQUIRE_JSON_ARRAY,
    NGX_AUTH_REQUIRE_JSON_OBJECT
} ngx_auth_require_json_type_t;

/** Maximum JSON input size (1 MiB) */
#define NGX_AUTH_REQUIRE_MAX_JSON_SIZE  1048576

/**
 * Parse a JSON string into a JSON value
 *
 * @param[in] data  JSON string to parse
 *
 * @return Parsed JSON value (caller must call ngx_auth_require_json_free()),
 *         or NULL on parse error
 */
ngx_auth_require_json_t *ngx_auth_require_json_parse(ngx_str_t *data);

/**
 * Free a parsed JSON value
 *
 * @param[in] json  JSON value to free (safe to call with NULL)
 */
void ngx_auth_require_json_free(ngx_auth_require_json_t *json);

/**
 * Get the type of a JSON value
 *
 * @param[in] json  JSON value
 *
 * @return JSON value type
 */
ngx_auth_require_json_type_t ngx_auth_require_json_type(
    ngx_auth_require_json_t *json);

/**
 * Get a value from a JSON object by key
 *
 * @param[in] json  JSON object
 * @param[in] key   key name to look up
 *
 * @return JSON value for the key (borrowed reference, do not free),
 *         or NULL if not found or json is not an object
 */
ngx_auth_require_json_t *ngx_auth_require_json_object_get(
    ngx_auth_require_json_t *json, ngx_str_t *key);

/**
 * Get the number of elements in a JSON array
 *
 * @param[in] json  JSON array
 *
 * @return Number of elements, or 0 if json is not an array
 */
size_t ngx_auth_require_json_array_size(ngx_auth_require_json_t *json);

/**
 * Get an element from a JSON array by index
 *
 * @param[in] json   JSON array
 * @param[in] index  zero-based array index
 *
 * @return JSON value at the index (borrowed reference, do not free),
 *         or NULL if out of bounds or json is not an array
 */
ngx_auth_require_json_t *ngx_auth_require_json_array_get(
    ngx_auth_require_json_t *json, size_t index);

/**
 * Extract a string value from a JSON string node
 *
 * @param[in]  json   JSON string node
 * @param[out] value  extracted string (points into JSON internal storage)
 *
 * @return NGX_OK on success, NGX_ERROR if json is not a string
 */
ngx_int_t ngx_auth_require_json_string(ngx_auth_require_json_t *json,
    ngx_str_t *value);

/**
 * Extract an integer value from a JSON integer node
 *
 * @param[in]  json   JSON integer node
 * @param[out] value  extracted integer
 *
 * @return NGX_OK on success, NGX_ERROR if json is not an integer
 */
ngx_int_t ngx_auth_require_json_integer(ngx_auth_require_json_t *json,
    int64_t *value);

/**
 * Extract a real (double) value from a JSON real node
 *
 * @param[in]  json   JSON real node
 * @param[out] value  extracted double
 *
 * @return NGX_OK on success, NGX_ERROR if json is not a real
 */
ngx_int_t ngx_auth_require_json_real(ngx_auth_require_json_t *json,
    double *value);

/**
 * Extract a boolean value from a JSON boolean node
 *
 * @param[in]  json   JSON boolean node
 * @param[out] value  extracted boolean (1 = true, 0 = false)
 *
 * @return NGX_OK on success, NGX_ERROR if json is not a boolean
 */
ngx_int_t ngx_auth_require_json_boolean(ngx_auth_require_json_t *json,
    ngx_flag_t *value);

/**
 * Create a JSON string node from an nginx string
 *
 * @param[in] str  string value
 *
 * @return New JSON string node (caller must call ngx_auth_require_json_free()),
 *         or NULL on failure
 */
ngx_auth_require_json_t *ngx_auth_require_json_from_string(ngx_str_t *str);

/**
 * Compare two JSON values for equality
 *
 * @param[in] a  first JSON value
 * @param[in] b  second JSON value
 *
 * @return 1 if equal, 0 if not equal
 */
ngx_flag_t ngx_auth_require_json_equal(ngx_auth_require_json_t *a,
    ngx_auth_require_json_t *b);

/**
 * Extract a numeric value as double from a JSON integer or real node
 *
 * Note: integer values exceeding 2^53 will lose precision when converted
 * to double.  For precision-preserving numeric comparison, use
 * ngx_auth_require_json_compare() instead.
 *
 * @param[in]  json   JSON integer or real node
 * @param[out] value  extracted double
 *
 * @return NGX_OK on success, NGX_ERROR if json is not a number
 */
ngx_int_t ngx_auth_require_json_number(ngx_auth_require_json_t *json,
    double *value);

/**
 * Compare two JSON numeric values with integer precision preservation
 *
 * When both values are integers, uses int64_t comparison directly.
 * Otherwise, falls back to double comparison (with DEBUG log when
 * precision loss is possible for integers > 2^53).
 *
 * @param[in]  a     first JSON numeric value
 * @param[in]  b     second JSON numeric value
 * @param[out] diff  comparison result (-1.0, 0.0, or 1.0)
 * @param[in]  log   nginx log for debug output (may be NULL)
 *
 * @return NGX_OK on success, NGX_ERROR if either value is not a number
 */
ngx_int_t ngx_auth_require_json_compare(ngx_auth_require_json_t *a,
    ngx_auth_require_json_t *b, double *diff, ngx_log_t *log);

/** @name Type checking macros */
/** @{ */

/** @def ngx_auth_require_json_is_string
 *  Check if a JSON value is a string */
#define ngx_auth_require_json_is_string(json)                                \
        (ngx_auth_require_json_type(json) == NGX_AUTH_REQUIRE_JSON_STRING)

/** @def ngx_auth_require_json_is_integer
*  Check if a JSON value is an integer */
#define ngx_auth_require_json_is_integer(json)                               \
        (ngx_auth_require_json_type(json) == NGX_AUTH_REQUIRE_JSON_INTEGER)

/** @def ngx_auth_require_json_is_real
 *  Check if a JSON value is a real number */
#define ngx_auth_require_json_is_real(json)                                  \
        (ngx_auth_require_json_type(json) == NGX_AUTH_REQUIRE_JSON_REAL)

/** @def ngx_auth_require_json_is_boolean
 *  Check if a JSON value is a boolean */
#define ngx_auth_require_json_is_boolean(json)                               \
        (ngx_auth_require_json_type(json) == NGX_AUTH_REQUIRE_JSON_BOOLEAN)

/** @def ngx_auth_require_json_is_array
*  Check if a JSON value is an array */
#define ngx_auth_require_json_is_array(json)                                 \
        (ngx_auth_require_json_type(json) == NGX_AUTH_REQUIRE_JSON_ARRAY)

/** @def ngx_auth_require_json_is_object
*  Check if a JSON value is an object */
#define ngx_auth_require_json_is_object(json)                                \
        (ngx_auth_require_json_type(json) == NGX_AUTH_REQUIRE_JSON_OBJECT)

/** @def ngx_auth_require_json_is_null
 *  Check if a JSON value is null */
#define ngx_auth_require_json_is_null(json)                                  \
        (ngx_auth_require_json_type(json) == NGX_AUTH_REQUIRE_JSON_NULL)

/** @} */

#endif /* _NGX_AUTH_REQUIRE_JSON_H_INCLUDED_ */
