/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * Operator table and comparison logic for auth_gate module
 *
 * Implements 8 operators: eq, gt, ge, lt, le, in, any, match.
 * Negation (! prefix) is handled in the lookup function.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_auth_gate_operator.h"

#define NGX_AUTH_GATE_MAX_ARRAY_SIZE      1024
#define NGX_AUTH_GATE_MAX_COMPARE_COUNT   10000

#define NGX_AUTH_GATE_MATCH_LIMIT         100000
#define NGX_AUTH_GATE_MATCH_LIMIT_DEPTH   100000

static ngx_int_t op_eq(nxe_json_t *actual,
    nxe_json_t *expected, ngx_pool_t *pool);
static ngx_int_t op_gt(nxe_json_t *actual,
    nxe_json_t *expected, ngx_pool_t *pool);
static ngx_int_t op_ge(nxe_json_t *actual,
    nxe_json_t *expected, ngx_pool_t *pool);
static ngx_int_t op_lt(nxe_json_t *actual,
    nxe_json_t *expected, ngx_pool_t *pool);
static ngx_int_t op_le(nxe_json_t *actual,
    nxe_json_t *expected, ngx_pool_t *pool);
static ngx_int_t op_in(nxe_json_t *actual,
    nxe_json_t *expected, ngx_pool_t *pool);
static ngx_int_t op_any(nxe_json_t *actual,
    nxe_json_t *expected, ngx_pool_t *pool);
#if (NGX_PCRE)
static ngx_int_t op_match(nxe_json_t *actual,
    nxe_json_t *expected, ngx_pool_t *pool);
#endif

static ngx_int_t op_compare_numbers(nxe_json_t *actual,
    nxe_json_t *expected, double *diff, ngx_log_t *log);
static ngx_int_t op_compare_strings(nxe_json_t *actual,
    nxe_json_t *expected, ngx_int_t *diff);

typedef struct {
    ngx_str_t                  name;
    ngx_auth_gate_operator_pt  handler;
} op_entry_t;

static op_entry_t operators[] = {
    { ngx_string("eq"),    op_eq },
    { ngx_string("gt"),    op_gt },
    { ngx_string("ge"),    op_ge },
    { ngx_string("lt"),    op_lt },
    { ngx_string("le"),    op_le },
    { ngx_string("in"),    op_in },
    { ngx_string("any"),   op_any },
#if (NGX_PCRE)
    { ngx_string("match"), op_match },
#endif
    { ngx_null_string, NULL }
};


/* Helper: numeric comparison preserving int64_t precision */
static ngx_int_t
op_compare_numbers(nxe_json_t *actual,
    nxe_json_t *expected, double *diff, ngx_log_t *log)
{
    return nxe_json_compare(actual, expected, diff, log);
}


/*
 * Helper: extract string values from two JSON values for comparison.
 * Returns NGX_OK with ngx_memn2cmp result in *diff.
 */
static ngx_int_t
op_compare_strings(nxe_json_t *actual,
    nxe_json_t *expected, ngx_int_t *diff)
{
    ngx_str_t a, e;

    if (nxe_json_string(actual, &a) != NGX_OK
        || nxe_json_string(expected, &e) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * Byte-order comparison (unsigned char values, shorter string is
     * "less").  This is locale-independent but means e.g. "9" > "10".
     * For numeric ordering, operands should use the json= prefix.
     */
    *diff = ngx_memn2cmp(a.data, e.data, a.len, e.len);

    return NGX_OK;
}


/* eq: JSON deep equality comparison */
static ngx_int_t
op_eq(nxe_json_t *actual, nxe_json_t *expected,
    ngx_pool_t *pool)
{
    return nxe_json_equal(actual, expected)
           ? NGX_OK : NGX_DECLINED;
}


/* gt: numeric greater-than, or string lexicographic comparison */
static ngx_int_t
op_gt(nxe_json_t *actual, nxe_json_t *expected,
    ngx_pool_t *pool)
{
    double ndiff;
    ngx_int_t sdiff;

    if (op_compare_numbers(actual, expected, &ndiff, pool->log) == NGX_OK) {
        return (ndiff > 0) ? NGX_OK : NGX_DECLINED;
    }

    /*
     * String fallback: byte-order comparison, so "9" > "10".
     * Use json= prefix for numeric ordering.
     */
    if (op_compare_strings(actual, expected, &sdiff) == NGX_OK) {
        return (sdiff > 0) ? NGX_OK : NGX_DECLINED;
    }

    return NGX_ERROR;
}


/* ge: numeric greater-or-equal, or string lexicographic comparison */
static ngx_int_t
op_ge(nxe_json_t *actual, nxe_json_t *expected,
    ngx_pool_t *pool)
{
    double ndiff;
    ngx_int_t sdiff;

    if (op_compare_numbers(actual, expected, &ndiff, pool->log) == NGX_OK) {
        return (ndiff >= 0) ? NGX_OK : NGX_DECLINED;
    }

    /* String fallback: see comment in op_gt() */
    if (op_compare_strings(actual, expected, &sdiff) == NGX_OK) {
        return (sdiff >= 0) ? NGX_OK : NGX_DECLINED;
    }

    return NGX_ERROR;
}


/* lt: numeric less-than, or string lexicographic comparison */
static ngx_int_t
op_lt(nxe_json_t *actual, nxe_json_t *expected,
    ngx_pool_t *pool)
{
    double ndiff;
    ngx_int_t sdiff;

    if (op_compare_numbers(actual, expected, &ndiff, pool->log) == NGX_OK) {
        return (ndiff < 0) ? NGX_OK : NGX_DECLINED;
    }

    /* String fallback: see comment in op_gt() */
    if (op_compare_strings(actual, expected, &sdiff) == NGX_OK) {
        return (sdiff < 0) ? NGX_OK : NGX_DECLINED;
    }

    return NGX_ERROR;
}


/* le: numeric less-or-equal, or string lexicographic comparison */
static ngx_int_t
op_le(nxe_json_t *actual, nxe_json_t *expected,
    ngx_pool_t *pool)
{
    double ndiff;
    ngx_int_t sdiff;

    if (op_compare_numbers(actual, expected, &ndiff, pool->log) == NGX_OK) {
        return (ndiff <= 0) ? NGX_OK : NGX_DECLINED;
    }

    /* String fallback: see comment in op_gt() */
    if (op_compare_strings(actual, expected, &sdiff) == NGX_OK) {
        return (sdiff <= 0) ? NGX_OK : NGX_DECLINED;
    }

    return NGX_ERROR;
}


/*
 * in: check if actual value is contained in expected collection
 *
 * When expected is an array, checks whether any element equals actual.
 * When expected is an object, treats actual as a string key and checks
 * whether that key exists in the object.
 * Returns NGX_ERROR for all other expected types.
 */
static ngx_int_t
op_in(nxe_json_t *actual, nxe_json_t *expected,
    ngx_pool_t *pool)
{
    size_t i, size;
    nxe_json_t *elem;

    if (nxe_json_is_array(expected)) {
        size = nxe_json_array_size(expected);

        if (size > NGX_AUTH_GATE_MAX_ARRAY_SIZE) {
            ngx_log_error(NGX_LOG_WARN, pool->log, 0,
                          "auth_gate: in operator array size "
                          "exceeds limit (%d): %uz",
                          NGX_AUTH_GATE_MAX_ARRAY_SIZE, size);
            return NGX_ERROR;
        }

        for (i = 0; i < size; i++) {
            elem = nxe_json_array_get(expected, i);
            if (nxe_json_equal(actual, elem)) {
                return NGX_OK;
            }
        }

        return NGX_DECLINED;
    }

    if (nxe_json_is_object(expected)) {
        /* Object mode: O(1) key lookup, bounded by MAX_JSON_SIZE */
        ngx_str_t key;

        if (nxe_json_string(actual, &key) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, pool->log, 0,
                          "auth_gate: in operator object key lookup "
                          "requires a string value");
            return NGX_ERROR;
        }

        elem = nxe_json_object_get_ns(expected, &key);

        return (elem != NULL) ? NGX_OK : NGX_DECLINED;
    }

    return NGX_ERROR;
}


/* any: check if two arrays share any common element */
static ngx_int_t
op_any(nxe_json_t *actual, nxe_json_t *expected,
    ngx_pool_t *pool)
{
    size_t i, j, asize, esize;
    nxe_json_t *a, *e;

    if (!nxe_json_is_array(actual)
        || !nxe_json_is_array(expected))
    {
        return NGX_ERROR;
    }

    asize = nxe_json_array_size(actual);
    esize = nxe_json_array_size(expected);

    if (asize > NGX_AUTH_GATE_MAX_ARRAY_SIZE
        || esize > NGX_AUTH_GATE_MAX_ARRAY_SIZE)
    {
        ngx_log_error(NGX_LOG_WARN, pool->log, 0,
                      "auth_gate: any operator array size "
                      "exceeds limit (%d): actual=%uz, expected=%uz",
                      NGX_AUTH_GATE_MAX_ARRAY_SIZE, asize, esize);
        return NGX_ERROR;
    }

    if (esize > 0
        && asize > NGX_AUTH_GATE_MAX_COMPARE_COUNT / esize)
    {
        ngx_log_error(NGX_LOG_WARN, pool->log, 0,
                      "auth_gate: any operator comparison count "
                      "exceeds limit (%d): %uz * %uz",
                      NGX_AUTH_GATE_MAX_COMPARE_COUNT,
                      asize, esize);
        return NGX_ERROR;
    }

    for (i = 0; i < asize; i++) {
        a = nxe_json_array_get(actual, i);

        for (j = 0; j < esize; j++) {
            e = nxe_json_array_get(expected, j);

            if (nxe_json_equal(a, e)) {
                return NGX_OK;
            }
        }
    }

    return NGX_DECLINED;
}


/*
 * match: compile expected as PCRE regex, match against actual.
 * Both values must be JSON strings.
 */
#if (NGX_PCRE)
static ngx_int_t
op_match(nxe_json_t *actual, nxe_json_t *expected,
    ngx_pool_t *pool)
{
    ngx_str_t actual_str, pattern_str;
    ngx_regex_compile_t rc;
    u_char errstr[NGX_MAX_CONF_ERRSTR];

    if (nxe_json_string(actual, &actual_str) != NGX_OK
        || nxe_json_string(expected, &pattern_str) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (pattern_str.len > 8192) {
        ngx_log_error(NGX_LOG_WARN, pool->log, 0,
                      "auth_gate: match operator pattern size "
                      "exceeds limit (8192): %uz", pattern_str.len);
        return NGX_ERROR;
    }

    if (memchr(pattern_str.data, '\0', pattern_str.len) != NULL) {
        ngx_log_error(NGX_LOG_WARN, pool->log, 0,
                      "auth_gate: match operator pattern "
                      "contains embedded NUL byte");
        return NGX_ERROR;
    }

    if (memchr(actual_str.data, '\0', actual_str.len) != NULL) {
        ngx_log_error(NGX_LOG_WARN, pool->log, 0,
                      "auth_gate: match operator subject "
                      "contains embedded NUL byte");
        return NGX_ERROR;
    }

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    /*
     * Compiled regex is freed via pool cleanup on request termination.
     * Per-request limit (MAX_DYNAMIC_REGEX) caps memory accumulation.
     */
    rc.pool = pool;
    rc.pattern = pattern_str;
    rc.err.data = errstr;
    rc.err.len = NGX_MAX_CONF_ERRSTR;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, pool->log, 0,
                      "auth_gate: dynamic regex compile failed: %V",
                      &rc.err);
        return NGX_ERROR;
    }

    return ngx_auth_gate_regex_exec_limited(rc.regex, &actual_str,
                                            pool->log);
}
#endif


ngx_int_t
ngx_auth_gate_operator_find(ngx_str_t *name,
    ngx_auth_gate_operator_pt *op, ngx_flag_t *negate)
{
    ngx_str_t lookup;
    op_entry_t *entry;

    *negate = 0;

    if (name->len > 1 && name->data[0] == '!') {
        lookup.data = name->data + 1;
        lookup.len = name->len - 1;
        *negate = 1;

    } else {
        lookup = *name;
    }

    for (entry = operators; entry->name.len; entry++) {
        if (entry->name.len == lookup.len
            && ngx_strncmp(entry->name.data, lookup.data,
                           lookup.len) == 0)
        {
            *op = entry->handler;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


#if (NGX_PCRE)

ngx_int_t
ngx_auth_gate_regex_exec_limited(ngx_regex_t *re, ngx_str_t *s,
    ngx_log_t *log)
{
    int rc;

#if (NGX_PCRE2)
    pcre2_match_data *match_data;
    pcre2_match_context *mctx;

    mctx = pcre2_match_context_create(NULL);
    if (mctx == NULL) {
        return NGX_ERROR;
    }

    pcre2_set_match_limit(mctx, NGX_AUTH_GATE_MATCH_LIMIT);
    pcre2_set_depth_limit(mctx, NGX_AUTH_GATE_MATCH_LIMIT_DEPTH);

    match_data = pcre2_match_data_create(1, NULL);
    if (match_data == NULL) {
        pcre2_match_context_free(mctx);
        return NGX_ERROR;
    }

    rc = pcre2_match(re, s->data, s->len, 0, 0, match_data, mctx);

    pcre2_match_data_free(match_data);
    pcre2_match_context_free(mctx);

    if (rc == PCRE2_ERROR_MATCHLIMIT || rc == PCRE2_ERROR_DEPTHLIMIT) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "auth_gate: regex match limit exceeded");
        return NGX_ERROR;
    }

#else
    pcre_extra extra;

    ngx_memzero(&extra, sizeof(pcre_extra));

    extra.flags = PCRE_EXTRA_MATCH_LIMIT | PCRE_EXTRA_MATCH_LIMIT_RECURSION;
    extra.match_limit = NGX_AUTH_GATE_MATCH_LIMIT;
    extra.match_limit_recursion = NGX_AUTH_GATE_MATCH_LIMIT_DEPTH;

    rc = pcre_exec(re->code, &extra,
                   (const char *) s->data, s->len, 0, 0, NULL, 0);

    if (rc == PCRE_ERROR_MATCHLIMIT || rc == PCRE_ERROR_RECURSIONLIMIT) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "auth_gate: regex match limit exceeded");
        return NGX_ERROR;
    }
#endif

    if (rc >= 0) {
        return NGX_OK;
    }

#if (NGX_PCRE2)
    if (rc == PCRE2_ERROR_NOMATCH) {
        return NGX_DECLINED;
    }
#else
    if (rc == PCRE_ERROR_NOMATCH) {
        return NGX_DECLINED;
    }
#endif

    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "auth_gate: pcre match internal error: %d", rc);

    return NGX_ERROR;
}

#endif
