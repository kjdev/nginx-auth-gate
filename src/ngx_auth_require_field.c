/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * JQ-like field path parsing and JSON tree extraction
 *
 * Parses field paths like ".user.profile.role", ".keys[0]",
 * '.["https://example.com/claim"]' into segment arrays.
 * At request time, traverses the JSON tree using the segments.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_auth_require_field.h"

#define NGX_AUTH_REQUIRE_MAX_FIELD_DEPTH  32
#define NGX_AUTH_REQUIRE_MAX_FIELD_INDEX  65535


/*
 * Parse a simple identifier: [a-zA-Z_][a-zA-Z0-9_-]*
 * Reads until '.', '[', or end of string.
 *
 * The pool parameter is unused here but kept for API consistency
 * with field_parse_bracket(), which needs pool for string allocation.
 *
 * Dot-notation keys are restricted to [a-zA-Z_][a-zA-Z0-9_-]*.
 * Keys containing other characters (spaces, dots, Unicode, special
 * chars like '/') must use the bracket notation: .["special key"].
 */
static ngx_int_t
field_parse_key(ngx_pool_t *pool, u_char **pos, u_char *end,
    ngx_auth_require_field_segment_t *seg)
{
    u_char *start;

    start = *pos;

    /* First character: [a-zA-Z_] */
    if (*pos >= end
        || !((**pos >= 'a' && **pos <= 'z')
             || (**pos >= 'A' && **pos <= 'Z')
             || **pos == '_'))
    {
        return NGX_ERROR;
    }

    (*pos)++;

    /* Subsequent characters: [a-zA-Z0-9_-] */
    while (*pos < end
           && ((**pos >= 'a' && **pos <= 'z')
               || (**pos >= 'A' && **pos <= 'Z')
               || (**pos >= '0' && **pos <= '9')
               || **pos == '_'
               || **pos == '-'))
    {
        (*pos)++;
    }

    seg->type = NGX_AUTH_REQUIRE_FIELD_KEY;
    seg->key.data = start;
    seg->key.len = *pos - start;
    seg->index = 0;

    return NGX_OK;
}


/*
 * Parse bracket notation:
 *   [0]     -> INDEX segment
 *   ["key"] -> KEY segment (quoted string)
 *
 * *pos points to '[' on entry, points past ']' on exit.
 */
static ngx_int_t
field_parse_bracket(ngx_pool_t *pool, u_char **pos, u_char *end,
    ngx_auth_require_field_segment_t *seg)
{
    u_char *p;
    ngx_int_t index;

    (*pos)++;

    if (*pos >= end) {
        return NGX_ERROR;
    }

    /* Quoted key: ["key"] */
    if (**pos == '"') {
        u_char *src, *dst, *key_data;
        size_t key_len;
        ngx_int_t has_escape;

        (*pos)++;

        /* first pass: find closing '"' and detect escapes */
        p = *pos;
        has_escape = 0;

        while (p < end && *p != '"') {
            if (*p == '\\' && p + 1 < end) {
                p++;
                if (*p != '"' && *p != '\\') {
                    return NGX_ERROR;
                }
                has_escape = 1;
            }
            p++;
        }

        if (p >= end || *p != '"') {
            return NGX_ERROR;
        }

        if (has_escape) {
            /* allocate and unescape */
            key_len = p - *pos;
            key_data = ngx_pnalloc(pool, key_len);
            if (key_data == NULL) {
                return NGX_ERROR;
            }

            src = *pos;
            dst = key_data;

            while (src < p) {
                if (*src == '\\' && src + 1 < p) {
                    src++;
                    if (*src != '"' && *src != '\\') {
                        return NGX_ERROR;
                    }
                }
                *dst++ = *src++;
            }

            seg->key.data = key_data;
            seg->key.len = dst - key_data;

        } else {
            seg->key.data = *pos;
            seg->key.len = p - *pos;
        }

        if (seg->key.len == 0) {
            /*
             * .[""] is syntactically valid and may legitimately appear
             * in JSON objects with empty-string keys.  Log a warning
             * since it is likely a configuration mistake, but do not
             * reject it.
             */
            ngx_log_error(NGX_LOG_WARN, pool->log, 0,
                          "auth_require: empty bracket key in field path");
        }

        seg->type = NGX_AUTH_REQUIRE_FIELD_KEY;
        seg->index = 0;

        p++;

        if (p >= end || *p != ']') {
            return NGX_ERROR;
        }

        p++;
        *pos = p;

        return NGX_OK;
    }

    /* Numeric index: [0] */
    p = *pos;

    while (p < end && *p >= '0' && *p <= '9') {
        p++;
    }

    if (p == *pos || p >= end || *p != ']') {
        return NGX_ERROR;
    }

    /* Reject leading zeros (e.g. [007]) but allow [0] */
    if (p - *pos > 1 && **pos == '0') {
        return NGX_ERROR;
    }

    index = ngx_atoi(*pos, p - *pos);
    if (index == NGX_ERROR
        || (size_t) index > NGX_AUTH_REQUIRE_MAX_FIELD_INDEX)
    {
        return NGX_ERROR;
    }

    seg->type = NGX_AUTH_REQUIRE_FIELD_INDEX;
    seg->key.data = NULL;
    seg->key.len = 0;
    seg->index = (size_t) index;

    p++;
    *pos = p;

    return NGX_OK;
}


ngx_int_t
ngx_auth_require_field_parse(ngx_pool_t *pool, ngx_str_t *raw,
    ngx_auth_require_field_path_t *path)
{
    u_char *p, *end;
    ngx_auth_require_field_segment_t *seg;

    if (raw == NULL || raw->len == 0 || raw->data[0] != '.') {
        return NGX_ERROR;
    }

    path->segments = ngx_array_create(pool, 4,
                                      sizeof(ngx_auth_require_field_segment_t));
    if (path->segments == NULL) {
        return NGX_ERROR;
    }

    /* Root path: just "." */
    if (raw->len == 1) {
        return NGX_OK;
    }

    p = raw->data + 1; /* skip leading '.' */
    end = raw->data + raw->len;

    /* Reject leading consecutive dots (e.g. "..key") */
    if (*p == '.') {
        return NGX_ERROR;
    }

    while (p < end) {

        if (path->segments->nelts >= NGX_AUTH_REQUIRE_MAX_FIELD_DEPTH) {
            return NGX_ERROR;
        }

        seg = ngx_array_push(path->segments);
        if (seg == NULL) {
            return NGX_ERROR;
        }

        if (*p == '[') {
            /* Bracket notation: [0] or ["key"] */
            if (field_parse_bracket(pool, &p, end, seg) != NGX_OK) {
                return NGX_ERROR;
            }

            /* After ']', only '.', '[', or end is valid */
            if (p < end && *p != '.' && *p != '[') {
                return NGX_ERROR;
            }

        } else if (*p == '.') {
            /* Dot separator: skip and parse next key or bracket */
            p++;

            if (p >= end) {
                return NGX_ERROR;
            }

            /* Reject consecutive dots (e.g. "..key") */
            if (*p == '.') {
                return NGX_ERROR;
            }

            if (*p == '[') {
                if (field_parse_bracket(pool, &p, end, seg) != NGX_OK) {
                    return NGX_ERROR;
                }

                /* After ']', only '.', '[', or end is valid */
                if (p < end && *p != '.' && *p != '[') {
                    return NGX_ERROR;
                }

            } else {
                if (field_parse_key(pool, &p, end, seg) != NGX_OK) {
                    return NGX_ERROR;
                }
            }

        } else {
            /* Identifier key */
            if (field_parse_key(pool, &p, end, seg) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


ngx_auth_require_json_t *
ngx_auth_require_field_get(ngx_auth_require_json_t *root,
    ngx_auth_require_field_path_t *path)
{
    ngx_uint_t i;
    ngx_auth_require_field_segment_t *segments;
    ngx_auth_require_json_t *current;

    if (root == NULL || path == NULL || path->segments == NULL) {
        return NULL;
    }

    /* Root path: empty segments array */
    if (path->segments->nelts == 0) {
        return root;
    }

    current = root;
    segments = path->segments->elts;

    for (i = 0; i < path->segments->nelts; i++) {

        switch (segments[i].type) {

        case NGX_AUTH_REQUIRE_FIELD_KEY:
            current = ngx_auth_require_json_object_get(current,
                                                       &segments[i].key);
            break;

        case NGX_AUTH_REQUIRE_FIELD_INDEX:
            current = ngx_auth_require_json_array_get(current,
                                                      segments[i].index);
            break;

        default:
            current = NULL;
            break;
        }

        if (current == NULL) {
            return NULL;
        }
    }

    return current;
}


static ngx_int_t
field_is_identifier_key(ngx_str_t *key)
{
    size_t i;

    if (key->len == 0) {
        return 0;
    }

    /* First character: [a-zA-Z_] */
    if (!((key->data[0] >= 'a' && key->data[0] <= 'z')
          || (key->data[0] >= 'A' && key->data[0] <= 'Z')
          || key->data[0] == '_'))
    {
        return 0;
    }

    /* Subsequent characters: [a-zA-Z0-9_-] */
    for (i = 1; i < key->len; i++) {
        if (!((key->data[i] >= 'a' && key->data[i] <= 'z')
              || (key->data[i] >= 'A' && key->data[i] <= 'Z')
              || (key->data[i] >= '0' && key->data[i] <= '9')
              || key->data[i] == '_'
              || key->data[i] == '-'))
        {
            return 0;
        }
    }

    return 1;
}


static size_t
field_count_escapes(ngx_str_t *key)
{
    size_t i, count;

    count = 0;
    for (i = 0; i < key->len; i++) {
        if (key->data[i] == '"' || key->data[i] == '\\') {
            count++;
        }
    }

    return count;
}


ngx_str_t
ngx_auth_require_field_path_str(ngx_auth_require_field_path_t *field,
    ngx_pool_t *pool)
{
    size_t i, k, len;
    u_char *p;
    ngx_str_t result;
    ngx_auth_require_field_segment_t *segments;

    ngx_str_null(&result);

    if (field == NULL || field->segments == NULL
        || field->segments->nelts == 0)
    {
        /* root path */
        result.data = ngx_pnalloc(pool, 1);
        if (result.data == NULL) {
            return result;
        }
        result.data[0] = '.';
        result.len = 1;
        return result;
    }

    segments = field->segments->elts;

    /* calculate total length */
    len = 0;
    for (i = 0; i < field->segments->nelts; i++) {
        if (segments[i].type == NGX_AUTH_REQUIRE_FIELD_KEY) {
            if (field_is_identifier_key(&segments[i].key)) {
                len += 1 + segments[i].key.len;   /* ".key" */
            } else {
                /* .[" key "] with escapes for '"' and '\\' */
                len += 5 + segments[i].key.len
                       + field_count_escapes(&segments[i].key);
            }
        } else {
            len += NGX_SIZE_T_LEN + 2;        /* "[index]" */
        }
    }

    result.data = ngx_pnalloc(pool, len);
    if (result.data == NULL) {
        return result;
    }

    p = result.data;
    for (i = 0; i < field->segments->nelts; i++) {
        if (segments[i].type == NGX_AUTH_REQUIRE_FIELD_KEY) {
            if (field_is_identifier_key(&segments[i].key)) {
                *p++ = '.';
                p = ngx_cpymem(p, segments[i].key.data, segments[i].key.len);
            } else {
                *p++ = '.';
                *p++ = '[';
                *p++ = '"';
                for (k = 0; k < segments[i].key.len; k++) {
                    if (segments[i].key.data[k] == '"'
                        || segments[i].key.data[k] == '\\')
                    {
                        *p++ = '\\';
                    }
                    *p++ = segments[i].key.data[k];
                }
                *p++ = '"';
                *p++ = ']';
            }
        } else {
            p = ngx_slprintf(p, result.data + len, "[%uz]",
                             segments[i].index);
        }
    }

    result.len = p - result.data;
    return result;
}
