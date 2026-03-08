/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_auth_gate_module.h"
#include "ngx_auth_gate_json.h"
#include "ngx_auth_gate_jwt.h"
#include "ngx_auth_gate_jws.h"

#define NGX_HTTP_AUTH_GATE_DEFAULT_ERROR  NGX_HTTP_FORBIDDEN
#define NGX_HTTP_AUTH_GATE_JSON_PREFIX_LEN  5

/* Maximum dynamic PCRE compilations per request */
#define NGX_HTTP_AUTH_GATE_MAX_DYNAMIC_REGEX  16

/* Maximum expected value size (bytes) to prevent DoS via large JSON parse */
#define NGX_HTTP_AUTH_GATE_MAX_EXPECTED_SIZE  65536

/* Configuration lifecycle */
static void *ngx_http_auth_gate_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_gate_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

/* Module initialization */
static ngx_int_t ngx_http_auth_gate_init(ngx_conf_t *cf);

/* Directive handlers */
static char *ngx_http_auth_gate_conf_set_require(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_gate_conf_set_json(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_gate_conf_set_jwt(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_gate_conf_set_jwt_verify(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

/* Variable handler */
static ngx_int_t require_variable_epoch(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/* Access handler */
static ngx_int_t ngx_http_auth_gate_access_handler(ngx_http_request_t *r);

/* Internal validation functions */
static ngx_int_t require_validate_vars(ngx_http_request_t *r,
    ngx_http_auth_gate_loc_conf_t *lcf);
static ngx_int_t require_validate_compare(ngx_http_request_t *r,
    ngx_http_auth_gate_loc_conf_t *lcf);
static ngx_int_t require_validate_json(ngx_http_request_t *r,
    ngx_http_auth_gate_loc_conf_t *lcf);
static ngx_int_t require_validate_jwt(ngx_http_request_t *r,
    ngx_http_auth_gate_loc_conf_t *lcf);
static ngx_int_t require_validate_requirement(ngx_http_request_t *r,
    ngx_auth_gate_requirement_t *req, ngx_auth_gate_json_t *root);

/* Configuration parsing helpers */
static ngx_int_t require_parse_error(ngx_conf_t *cf, ngx_str_t *value,
    ngx_int_t *error);
static char *require_parse_requirement(ngx_conf_t *cf, ngx_str_t *args,
    ngx_uint_t nargs, ngx_auth_gate_requirement_t *req,
    ngx_flag_t parse_field);

/* Configuration merge helpers */
static ngx_int_t require_merge_array(ngx_conf_t *cf, ngx_array_t **prev,
    ngx_array_t **conf, size_t size);
static ngx_int_t require_merge_groups(ngx_conf_t *cf, ngx_array_t **prev,
    ngx_array_t **conf);
static ngx_int_t require_merge_jwt_verify(ngx_conf_t *cf, ngx_array_t **prev,
    ngx_array_t **conf);

/* Variable group helpers */
static ngx_auth_gate_var_group_t *require_find_group(ngx_array_t *groups,
    ngx_str_t *variable_name);


/* Variable definitions */
static ngx_http_variable_t require_vars[] = {

    { ngx_string("auth_gate_epoch"), NULL,
      require_variable_epoch,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    ngx_http_null_variable
};


static ngx_command_t ngx_http_auth_gate_commands[] = {

    { ngx_string("auth_gate"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_HTTP_LMT_CONF | NGX_CONF_1MORE,
      ngx_http_auth_gate_conf_set_require,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_gate_json"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_HTTP_LMT_CONF | NGX_CONF_2MORE,
      ngx_http_auth_gate_conf_set_json,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_gate_jwt"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_HTTP_LMT_CONF | NGX_CONF_2MORE,
      ngx_http_auth_gate_conf_set_jwt,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_gate_jwt_verify"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_HTTP_LMT_CONF | NGX_CONF_2MORE,
      ngx_http_auth_gate_conf_set_jwt_verify,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_auth_gate_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_auth_gate_init,             /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_http_auth_gate_create_loc_conf,  /* create location configuration */
    ngx_http_auth_gate_merge_loc_conf    /* merge location configuration */
};

ngx_module_t ngx_http_auth_gate_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_gate_module_ctx,  /* module context */
    ngx_http_auth_gate_commands,     /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


/* Forward declarations for JWT verify subrequest handling */
static ngx_int_t jwt_verify_start(ngx_http_request_t *r,
    ngx_http_auth_gate_loc_conf_t *lcf);
static ngx_int_t jwt_verify_execute(ngx_http_request_t *r,
    ngx_http_auth_gate_loc_conf_t *lcf, ngx_http_auth_gate_ctx_t *ctx);
static ngx_int_t jwks_post_subrequest_handler(ngx_http_request_t *r,
    void *data, ngx_int_t rc);


/*
 * ACCESS phase handler
 *
 * Evaluates all auth_gate directives in order:
 * 0. JWT signature verification (async, subrequest-based)
 * 1. require_vars (boolean check mode)
 * 2. require_compare (auth_gate with operator)
 * 3. require_json (auth_gate_json)
 * 4. require_jwt (auth_gate_jwt)
 */
static ngx_int_t
ngx_http_auth_gate_access_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_http_auth_gate_loc_conf_t *lcf;
    ngx_http_auth_gate_ctx_t *ctx;

    /* Skip subrequests to prevent recursion */
    if (r != r->main) {
        return NGX_DECLINED;
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_gate_module);

    if (lcf->require_vars == NULL
        && lcf->require_compare == NULL
        && lcf->require_json == NULL
        && lcf->require_jwt == NULL
        && lcf->require_jwt_verify == NULL)
    {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth_gate: access handler");

    /* 0. JWT signature verification (async) */
    if (lcf->require_jwt_verify != NULL) {
        ctx = ngx_http_get_module_ctx(r, ngx_http_auth_gate_module);

        if (ctx == NULL || !ctx->jwt_verify_started) {
            /* First entry: start subrequests */
            rc = jwt_verify_start(r, lcf);
            if (rc != NGX_OK) {
                return rc;  /* NGX_AGAIN or error */
            }
            /* rc == NGX_OK means 0 unique URIs (shouldn't happen) */
        } else if (!ctx->jwt_verify_done) {
            if (ctx->jwks_fetched < ctx->jwks_expected) {
                /* Still waiting for subrequests */
                return NGX_AGAIN;
            }

            /* All JWKS fetched, execute verification */
            rc = jwt_verify_execute(r, lcf, ctx);
            if (rc != NGX_OK) {
                return rc;
            }

            ctx->jwt_verify_done = 1;
        }
    }

    /* 1. Boolean check mode */
    if (lcf->require_vars != NULL) {
        rc = require_validate_vars(r, lcf);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    /* 2. Comparison mode */
    if (lcf->require_compare != NULL) {
        rc = require_validate_compare(r, lcf);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    /* 3. JSON field validation */
    if (lcf->require_json != NULL) {
        rc = require_validate_json(r, lcf);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    /* 4. JWT claim validation */
    if (lcf->require_jwt != NULL) {
        rc = require_validate_jwt(r, lcf);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}


/*
 * Validate boolean check variables (commercial-compatible).
 * A value is "false" if empty or "0".
 */
static ngx_int_t
require_validate_vars(ngx_http_request_t *r,
    ngx_http_auth_gate_loc_conf_t *lcf)
{
    ngx_uint_t i, j;
    ngx_str_t val;
    ngx_http_auth_gate_var_t *vars;
    ngx_http_complex_value_t *values;

    vars = lcf->require_vars->elts;

    for (i = 0; i < lcf->require_vars->nelts; i++) {
        values = vars[i].values->elts;

        for (j = 0; j < vars[i].values->nelts; j++) {

            if (ngx_http_complex_value(r, &values[j], &val) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "auth_gate: failed to evaluate variable "
                              "(var #%ui of %ui)",
                              j + 1, vars[i].values->nelts);
                return vars[i].error;
            }

            /* Commercial-compatible: empty or "0" is false */
            if (val.len == 0
                || (val.len == 1 && val.data[0] == '0'))
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "auth_gate: variable check failed "
                              "(var #%ui of %ui)",
                              j + 1, vars[i].values->nelts);
                return vars[i].error;
            }
        }
    }

    return NGX_OK;
}


/*
 * Validate auth_gate comparison mode.
 * Variable value is wrapped as a JSON string for operator comparison.
 *
 * Memory ownership:
 *   - actual (JSON string): created and freed within this function.
 *   - expected: managed by require_validate_requirement().
 */
static ngx_int_t
require_validate_compare(ngx_http_request_t *r,
    ngx_http_auth_gate_loc_conf_t *lcf)
{
    ngx_uint_t i;
    ngx_int_t rc;
    ngx_str_t val;
    ngx_auth_gate_requirement_t *reqs;
    ngx_auth_gate_json_t *actual;

    reqs = lcf->require_compare->elts;

    for (i = 0; i < lcf->require_compare->nelts; i++) {

        if (ngx_http_complex_value(r, reqs[i].variable, &val) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate: failed to evaluate variable");
            return reqs[i].error;
        }

        /* Wrap string value as JSON string for comparison */
        actual = ngx_auth_gate_json_from_string(&val);
        if (actual == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate: failed to create JSON "
                          "from variable value");
            return reqs[i].error;
        }

        rc = require_validate_requirement(r, &reqs[i], actual);
        ngx_auth_gate_json_free(actual);

        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}


/*
 * Validate auth_gate_json directives.
 * Variable value is parsed once per group, then all requirements validated.
 */
static ngx_int_t
require_validate_json(ngx_http_request_t *r,
    ngx_http_auth_gate_loc_conf_t *lcf)
{
    ngx_uint_t i, j;
    ngx_int_t rc;
    ngx_str_t val;
    ngx_auth_gate_var_group_t *groups;
    ngx_auth_gate_requirement_t *reqs;
    ngx_auth_gate_json_t *json;

    groups = lcf->require_json->elts;

    for (i = 0; i < lcf->require_json->nelts; i++) {

        if (ngx_http_complex_value(r, groups[i].variable, &val) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate_json: failed to evaluate variable");
            reqs = groups[i].requirements->elts;
            /*
             * Use reqs[0].error: variable evaluation failed before any
             * individual requirement could be tested, so we return the
             * first requirement's error code as a reasonable default.
             */
            return reqs[0].error;
        }

        json = ngx_auth_gate_json_parse(&val);
        if (json == NULL) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "auth_gate_json: JSON parse failed");
            reqs = groups[i].requirements->elts;
            /* Same rationale as variable evaluation failure above */
            return reqs[0].error;
        }

        if (!ngx_auth_gate_json_is_object(json)
            && !ngx_auth_gate_json_is_array(json))
        {
            reqs = groups[i].requirements->elts;

            for (j = 0; j < groups[i].requirements->nelts; j++) {
                if (reqs[j].field.segments->nelts > 0) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                                  "auth_gate_json: parsed value is a "
                                  "scalar (type=%d); field path requires "
                                  "an object or array as root value",
                                  ngx_auth_gate_json_type(json));
                    ngx_auth_gate_json_free(json);
                    return reqs[j].error;
                }
            }
        }

        reqs = groups[i].requirements->elts;

        for (j = 0; j < groups[i].requirements->nelts; j++) {
            rc = require_validate_requirement(r, &reqs[j], json);
            if (rc != NGX_OK) {
                ngx_auth_gate_json_free(json);
                return rc;
            }
        }

        ngx_auth_gate_json_free(json);
    }

    return NGX_OK;
}


/*
 * Validate auth_gate_jwt directives.
 * Variable value is decoded once per group, then all requirements validated.
 */
static ngx_int_t
require_validate_jwt(ngx_http_request_t *r,
    ngx_http_auth_gate_loc_conf_t *lcf)
{
    ngx_uint_t i, j;
    ngx_int_t rc;
    ngx_str_t val;
    ngx_auth_gate_var_group_t *groups;
    ngx_auth_gate_requirement_t *reqs;
    ngx_auth_gate_json_t *json;

    groups = lcf->require_jwt->elts;

    for (i = 0; i < lcf->require_jwt->nelts; i++) {

        if (ngx_http_complex_value(r, groups[i].variable, &val) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate_jwt: failed to evaluate variable");
            reqs = groups[i].requirements->elts;
            /*
             * Use reqs[0].error: variable evaluation failed before any
             * individual requirement could be tested, so we return the
             * first requirement's error code as a reasonable default.
             */
            return reqs[0].error;
        }

        json = ngx_auth_gate_jwt_decode_payload(&val, r->pool);
        if (json == NULL) {
            /* Specific failure reason already logged by decode function */
            reqs = groups[i].requirements->elts;
            /* Same rationale as variable evaluation failure above */
            return reqs[0].error;
        }

        if (!ngx_auth_gate_json_is_object(json)
            && !ngx_auth_gate_json_is_array(json))
        {
            reqs = groups[i].requirements->elts;

            for (j = 0; j < groups[i].requirements->nelts; j++) {
                if (reqs[j].field.segments->nelts > 0) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                                  "auth_gate_jwt: decoded payload is a "
                                  "scalar (type=%d); field path requires "
                                  "an object or array as root value",
                                  ngx_auth_gate_json_type(json));
                    ngx_auth_gate_json_free(json);
                    return reqs[j].error;
                }
            }
        }

        reqs = groups[i].requirements->elts;

        for (j = 0; j < groups[i].requirements->nelts; j++) {
            rc = require_validate_requirement(r, &reqs[j], json);
            if (rc != NGX_OK) {
                ngx_auth_gate_json_free(json);
                return rc;
            }
        }

        ngx_auth_gate_json_free(json);
    }

    return NGX_OK;
}


/*
 * Common validation logic for auth_gate_json and auth_gate_jwt.
 * Extracts field from JSON root, parses expected value,
 * applies operator, and handles negation.
 *
 * Memory ownership:
 *   - root: owned by caller; this function does NOT free it.
 *   - expected: created and freed within this function.
 */
static ngx_int_t
require_validate_requirement(ngx_http_request_t *r,
    ngx_auth_gate_requirement_t *req, ngx_auth_gate_json_t *root)
{
    ngx_int_t rc;
    ngx_str_t expected_str;
    ngx_str_t field_str;
    ngx_auth_gate_json_t *actual, *expected = NULL;

    static const ngx_str_t unknown = ngx_string("(unknown)");

    /* Reconstruct field path string for log messages */
    field_str = ngx_auth_gate_field_path_str(&req->field, r->pool);
    if (field_str.data == NULL) {
        field_str = *(ngx_str_t *) &unknown;
    }

    /* actual: borrowed reference from root (not owned, do not free) */

    /* 1. Extract field (empty segments = root) */
    actual = ngx_auth_gate_field_get(root, &req->field);
    if (actual == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "auth_gate: field not found: %V", &field_str);
        return req->error;
    }

    /* 2. Precompiled regex: skip expected evaluation entirely */

#if (NGX_PCRE)
    if (req->compiled_regex != NULL) {
        ngx_str_t actual_str;

        if (ngx_auth_gate_json_string(actual, &actual_str) != NGX_OK) {
            rc = NGX_ERROR;
        } else if (memchr(actual_str.data, '\0', actual_str.len) != NULL) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "auth_gate: match operator subject "
                          "contains embedded NUL byte, field: %V",
                          &field_str);
            rc = NGX_ERROR;
        } else {
            rc = ngx_auth_gate_regex_exec_limited(
                req->compiled_regex, &actual_str,
                r->connection->log);
        }

        goto apply_negation;
    }
#endif

    /* 3. Evaluate expected value */
    if (ngx_http_complex_value(r, req->expected, &expected_str) != NGX_OK) {
        return req->error;
    }

    if (expected_str.len > NGX_HTTP_AUTH_GATE_MAX_EXPECTED_SIZE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_gate: expected value too large: %uz,"
                      " field: %V", expected_str.len, &field_str);
        return req->error;
    }

    if (req->expected_json) {
        expected = ngx_auth_gate_json_parse(&expected_str);
    } else {
        expected = ngx_auth_gate_json_from_string(&expected_str);
    }

    if (expected == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "auth_gate: expected value parse failed,"
                      " field: %V", &field_str);
        return req->error;
    }

    /* 4. Apply operator */

#if (NGX_PCRE)
    /* Rate-limit dynamic regex compilations per request */
    {
        ngx_str_t stripped;

        stripped = req->operator_name;

        if (stripped.len > 0 && stripped.data[0] == '!') {
            stripped.data++;
            stripped.len--;
        }

        if (stripped.len == 5
            && ngx_strncmp(stripped.data, "match", 5) == 0)
        {
            ngx_http_auth_gate_ctx_t *ctx;

            ctx = ngx_http_get_module_ctx(r,
                                          ngx_http_auth_gate_module);
            if (ctx == NULL) {
                ctx = ngx_pcalloc(r->pool,
                                  sizeof(ngx_http_auth_gate_ctx_t));
                if (ctx == NULL) {
                    ngx_auth_gate_json_free(expected);
                    return req->error;
                }
                ngx_http_set_ctx(r, ctx,
                                 ngx_http_auth_gate_module);
            }

            if (ctx->dynamic_regex_count
                >= NGX_HTTP_AUTH_GATE_MAX_DYNAMIC_REGEX)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "auth_gate: dynamic regex "
                              "compilation limit exceeded (%d),"
                              " field: %V",
                              NGX_HTTP_AUTH_GATE_MAX_DYNAMIC_REGEX,
                              &field_str);
                ngx_auth_gate_json_free(expected);
                return req->error;
            }

            ctx->dynamic_regex_count++;
        }
    }
#endif

    rc = req->operator(actual, expected, r->pool);

    ngx_auth_gate_json_free(expected);

    /* 5. Apply negation (NGX_ERROR is NOT flipped) */

apply_negation:

    if (req->negate) {
        if (rc == NGX_OK) {
            rc = NGX_DECLINED;
        } else if (rc == NGX_DECLINED) {
            rc = NGX_OK;
        }
        /* NGX_ERROR and any unexpected value pass through unchanged */
    }

    /* NGX_DECLINED, NGX_ERROR, or unexpected value → check failure */
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "auth_gate: %V check failed, field: %V",
                      &req->operator_name, &field_str);
        return req->error;
    }

    return NGX_OK;
}


/*
 * Parse error=NNN from a directive argument.
 * Returns NGX_OK if parsed, NGX_DECLINED if not an error= arg.
 */
static ngx_int_t
require_parse_error(ngx_conf_t *cf, ngx_str_t *value, ngx_int_t *error)
{
    ngx_int_t code;
    ngx_str_t code_str;

    if (value->len < 7
        || ngx_strncmp(value->data, "error=", 6) != 0)
    {
        return NGX_DECLINED;
    }

    code_str.data = value->data + 6;
    code_str.len = value->len - 6;

    code = ngx_atoi(code_str.data, code_str.len);
    if (code < 400 || code > 599 || code == 444 || code == 499) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gate: invalid error code \"%V\"", value);
        return NGX_ERROR;
    }

    *error = code;

    return NGX_OK;
}


/*
 * Parse a comparison requirement (operator mode).
 *
 * Expected args layout:
 *   [field] operator expected [error=NNN]
 *
 * If parse_field is true, first arg is the field path.
 * Otherwise, field is set to root (empty segments).
 */
static char *
require_parse_requirement(ngx_conf_t *cf, ngx_str_t *args,
    ngx_uint_t nargs, ngx_auth_gate_requirement_t *req,
    ngx_flag_t parse_field)
{
    ngx_uint_t idx;
    ngx_str_t *op_name, *expected_str;
    ngx_str_t json_value;
    ngx_http_compile_complex_value_t ccv;

    idx = 0;

    /* Parse field path (if applicable) */
    if (parse_field) {
        if (idx >= nargs) {
            return NGX_CONF_ERROR;
        }

        if (ngx_auth_gate_field_parse(cf->pool, &args[idx], &req->field)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_gate: invalid field path \"%V\"",
                               &args[idx]);
            return NGX_CONF_ERROR;
        }

        idx++;

    } else {
        /* No field: root path (empty segments) */
        req->field.segments = ngx_array_create(
            cf->pool, 1, sizeof(ngx_auth_gate_field_segment_t));
        if (req->field.segments == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    /* Parse operator */
    if (idx >= nargs) {
        return NGX_CONF_ERROR;
    }

    op_name = &args[idx];

    if (ngx_auth_gate_operator_find(op_name, &req->operator, &req->negate)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gate: unknown operator \"%V\"", op_name);
        return NGX_CONF_ERROR;
    }

    req->operator_name = *op_name;
    idx++;

    /* Parse expected value */
    if (idx >= nargs) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gate: expected value missing");
        return NGX_CONF_ERROR;
    }

    expected_str = &args[idx];

    /* Check json= prefix */
    req->expected_json = 0;

    if (expected_str->len >= NGX_HTTP_AUTH_GATE_JSON_PREFIX_LEN
        && ngx_strncmp(expected_str->data, "json=",
                       NGX_HTTP_AUTH_GATE_JSON_PREFIX_LEN) == 0)
    {
        if (expected_str->len == NGX_HTTP_AUTH_GATE_JSON_PREFIX_LEN) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_gate: empty JSON value "
                               "after \"json=\" prefix");
            return NGX_CONF_ERROR;
        }

        req->expected_json = 1;
        json_value.data = expected_str->data
                          + NGX_HTTP_AUTH_GATE_JSON_PREFIX_LEN;
        json_value.len = expected_str->len
                         - NGX_HTTP_AUTH_GATE_JSON_PREFIX_LEN;
        expected_str = &json_value;
    }

    /* Compile expected value as complex value */
    req->expected = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (req->expected == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = expected_str;
    ccv.complex_value = req->expected;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    idx++;

    /* Validate constant json= value at configure time */
    if (req->expected_json && req->expected->lengths == NULL) {
        ngx_auth_gate_json_t *test;

        test = ngx_auth_gate_json_parse(expected_str);
        if (test == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_gate: invalid JSON in "
                               "\"json=%V\"", expected_str);
            return NGX_CONF_ERROR;
        }

        ngx_auth_gate_json_free(test);
    }

#if (NGX_PCRE)
    /* Precompile regex for match operator with constant pattern */
    req->compiled_regex = NULL;

    if (req->expected->lengths == NULL) {
        ngx_str_t stripped;

        stripped = req->operator_name;

        if (stripped.len > 0 && stripped.data[0] == '!') {
            stripped.data++;
            stripped.len--;
        }

        if (stripped.len == 5
            && ngx_strncmp(stripped.data, "match", 5) == 0)
        {
            ngx_regex_compile_t rc;
            u_char errstr[NGX_MAX_CONF_ERRSTR];
            ngx_str_t pattern;

            pattern = *expected_str;

            /* json= prefix: parse JSON to extract the string pattern */
            if (req->expected_json) {
                ngx_auth_gate_json_t *json;
                ngx_str_t json_str;

                json = ngx_auth_gate_json_parse(expected_str);
                if (json == NULL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "auth_gate: invalid JSON in "
                                       "match pattern \"json=%V\"",
                                       expected_str);
                    return NGX_CONF_ERROR;
                }

                if (ngx_auth_gate_json_string(json, &json_str)
                    != NGX_OK)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "auth_gate: json= value for "
                                       "match must be a string");
                    ngx_auth_gate_json_free(json);
                    return NGX_CONF_ERROR;
                }

                pattern.data = ngx_pstrdup(cf->pool, &json_str);
                pattern.len = json_str.len;

                ngx_auth_gate_json_free(json);

                if (pattern.data == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

            rc.pool = cf->pool;
            rc.pattern = pattern;
            rc.err.data = errstr;
            rc.err.len = NGX_MAX_CONF_ERRSTR;

            if (ngx_regex_compile(&rc) != NGX_OK) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "auth_gate: invalid regex \"%V\": %V",
                                   expected_str, &rc.err);
                return NGX_CONF_ERROR;
            }

            req->compiled_regex = rc.regex;
        }

    } else {
        ngx_str_t stripped;

        stripped = req->operator_name;

        if (stripped.len > 0 && stripped.data[0] == '!') {
            stripped.data++;
            stripped.len--;
        }

        if (stripped.len == 5
            && ngx_strncmp(stripped.data, "match", 5) == 0)
        {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "auth_gate: match operator with dynamic "
                               "pattern compiles regex per request; "
                               "this is a ReDoS risk if pattern is derived "
                               "from untrusted input; "
                               "consider using a constant pattern");
        }
    }
#endif

    /* Parse optional error=NNN */
    req->error = NGX_HTTP_AUTH_GATE_DEFAULT_ERROR;

    if (idx < nargs) {
        ngx_int_t rc;

        rc = require_parse_error(cf, &args[idx], &req->error);
        if (rc == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        if (rc == NGX_DECLINED) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_gate: unexpected argument \"%V\"",
                               &args[idx]);
            return NGX_CONF_ERROR;
        }

        idx++;

        if (idx < nargs) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_gate: unexpected argument \"%V\"",
                               &args[idx]);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * auth_gate directive handler
 *
 * Detects mode based on 2nd argument:
 * - Starts with '$': additional variable (boolean check mode)
 * - Starts with 'error=': error code for boolean check
 * - Otherwise: operator (comparison mode)
 */
static char *
ngx_http_auth_gate_conf_set_require(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_gate_loc_conf_t *lcf = conf;

    ngx_str_t *values;
    ngx_uint_t i;
    ngx_http_auth_gate_var_t *var;
    ngx_auth_gate_requirement_t *req;
    ngx_http_complex_value_t *cv;
    ngx_http_compile_complex_value_t ccv;
    ngx_flag_t is_compare;
    ngx_flag_t error_set;

    values = cf->args->elts;

    /* values[1].len > 0 guaranteed by nginx config parser */
    if (values[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gate: first argument must be a variable");
        return NGX_CONF_ERROR;
    }

    /*
     * Detect mode:
     * - If only 1 arg after directive name, or 2nd arg starts with '$'
     *   or 'error=': boolean check mode
     * - Otherwise: comparison mode (operator detected)
     */
    is_compare = 0;

    if (cf->args->nelts >= 3) {
        ngx_str_t *arg2 = &values[2];

        if (arg2->data[0] != '$'
            && !(arg2->len >= 6
                 && ngx_strncmp(arg2->data, "error=", 6) == 0))
        {
            is_compare = 1;
        }
    }

    if (is_compare) {
        /* Comparison mode: $variable operator expected [error=NNN] */
        if (lcf->require_compare == NULL) {
            lcf->require_compare = ngx_array_create(
                cf->pool, 2, sizeof(ngx_auth_gate_requirement_t));
            if (lcf->require_compare == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        req = ngx_array_push(lcf->require_compare);
        if (req == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(req, sizeof(ngx_auth_gate_requirement_t));

        req->variable = ngx_palloc(cf->pool,
                                   sizeof(ngx_http_complex_value_t));
        if (req->variable == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &values[1];
        ccv.complex_value = req->variable;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        /* Parse remaining: operator expected [error=NNN] */
        return require_parse_requirement(cf, &values[2],
                                         cf->args->nelts - 2,
                                         req, 0);
    }

    /* Boolean check mode: $variable [...] [error=NNN] */
    if (lcf->require_vars == NULL) {
        lcf->require_vars = ngx_array_create(
            cf->pool, 2, sizeof(ngx_http_auth_gate_var_t));
        if (lcf->require_vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    var = ngx_array_push(lcf->require_vars);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->values = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                   sizeof(ngx_http_complex_value_t));
    if (var->values == NULL) {
        return NGX_CONF_ERROR;
    }

    var->error = NGX_HTTP_AUTH_GATE_DEFAULT_ERROR;
    error_set = 0;

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_int_t rc;

        rc = require_parse_error(cf, &values[i], &var->error);
        if (rc == NGX_OK) {
            if (error_set) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "auth_gate: duplicate error= "
                                   "specified, overriding with \"%V\"",
                                   &values[i]);
            }
            error_set = 1;
            continue;
        }
        if (rc == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        if (values[i].data[0] != '$') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_gate: "
                               "arguments must be variables");
            return NGX_CONF_ERROR;
        }

        cv = ngx_array_push(var->values);
        if (cv == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &values[i];
        ccv.complex_value = cv;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (var->values->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gate: no variables specified");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * auth_gate_json directive handler
 *
 * Syntax: auth_gate_json $variable <field> <operator> <expected>
 *                           [error=4xx|5xx];
 *
 * Groups requirements by variable name for single-parse optimization.
 */
static char *
ngx_http_auth_gate_conf_set_json(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_gate_loc_conf_t *lcf = conf;

    ngx_str_t *values;
    ngx_auth_gate_requirement_t *req;
    ngx_auth_gate_var_group_t *group;
    ngx_http_compile_complex_value_t ccv;

    values = cf->args->elts;

    /* values[1].len > 0 guaranteed by nginx config parser */
    if (values[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gate_json: "
                           "first argument must be a variable");
        return NGX_CONF_ERROR;
    }

    /* Second argument must be a field path (starts with '.') */
    if (values[2].data[0] != '.') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gate_json: "
                           "field path must start with '.': \"%V\"",
                           &values[2]);
        return NGX_CONF_ERROR;
    }

    if (lcf->require_json == NULL) {
        lcf->require_json = ngx_array_create(
            cf->pool, 2, sizeof(ngx_auth_gate_var_group_t));
        if (lcf->require_json == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    /* Find or create variable group */
    group = require_find_group(lcf->require_json, &values[1]);

    if (group == NULL) {
        group = ngx_array_push(lcf->require_json);
        if (group == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(group, sizeof(ngx_auth_gate_var_group_t));
        group->variable_name = values[1];

        group->variable = ngx_palloc(cf->pool,
                                     sizeof(ngx_http_complex_value_t));
        if (group->variable == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &values[1];
        ccv.complex_value = group->variable;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        group->requirements = ngx_array_create(
            cf->pool, 2, sizeof(ngx_auth_gate_requirement_t));
        if (group->requirements == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    req = ngx_array_push(group->requirements);
    if (req == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(req, sizeof(ngx_auth_gate_requirement_t));

    /* Parse: field operator expected [error=NNN] */
    return require_parse_requirement(cf, &values[2], cf->args->nelts - 2,
                                     req, 1);
}


/*
 * auth_gate_jwt directive handler
 *
 * Syntax: auth_gate_jwt $variable <claim> <operator> <expected>
 *                          [error=4xx|5xx];
 *
 * Groups requirements by variable name for single-decode optimization.
 */
static char *
ngx_http_auth_gate_conf_set_jwt(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_gate_loc_conf_t *lcf = conf;

    ngx_str_t *values;
    ngx_auth_gate_requirement_t *req;
    ngx_auth_gate_var_group_t *group;
    ngx_http_compile_complex_value_t ccv;

    values = cf->args->elts;

    /* values[1].len > 0 guaranteed by nginx config parser */
    if (values[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gate_jwt: "
                           "first argument must be a variable");
        return NGX_CONF_ERROR;
    }

    /* Second argument must be a field path (starts with '.') */
    if (values[2].data[0] != '.') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gate_jwt: "
                           "field path must start with '.': \"%V\"",
                           &values[2]);
        return NGX_CONF_ERROR;
    }

    if (lcf->require_jwt == NULL) {
        lcf->require_jwt = ngx_array_create(
            cf->pool, 2, sizeof(ngx_auth_gate_var_group_t));
        if (lcf->require_jwt == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    /* Find or create variable group */
    group = require_find_group(lcf->require_jwt, &values[1]);

    if (group == NULL) {
        group = ngx_array_push(lcf->require_jwt);
        if (group == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(group, sizeof(ngx_auth_gate_var_group_t));
        group->variable_name = values[1];

        group->variable = ngx_palloc(cf->pool,
                                     sizeof(ngx_http_complex_value_t));
        if (group->variable == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &values[1];
        ccv.complex_value = group->variable;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        group->requirements = ngx_array_create(
            cf->pool, 2, sizeof(ngx_auth_gate_requirement_t));
        if (group->requirements == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    req = ngx_array_push(group->requirements);
    if (req == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(req, sizeof(ngx_auth_gate_requirement_t));

    /* Parse: claim operator expected [error=NNN] */
    return require_parse_requirement(cf, &values[2], cf->args->nelts - 2,
                                     req, 1);
}


/*
 * Merge two arrays: prepend parent entries, then append child entries.
 * If child is NULL, inherit parent. If parent is NULL, keep child.
 */
static ngx_int_t
require_merge_array(ngx_conf_t *cf, ngx_array_t **prev, ngx_array_t **conf,
    size_t size)
{
    ngx_array_t *merged;

    if (*conf == NULL) {
        *conf = *prev;
        return NGX_OK;
    }

    if (*prev == NULL) {
        return NGX_OK;
    }

    /* Both defined: merge parent + child */
    merged = ngx_array_create(cf->pool,
                              (*prev)->nelts + (*conf)->nelts, size);
    if (merged == NULL) {
        return NGX_ERROR;
    }

    /*
     * Shallow copy: element structs are copied by value.  Pointers within
     * them (e.g. compiled complex values, regex) still reference the
     * original cf->pool allocations, which is safe because cf->pool
     * outlives all request processing for this location.
     */

    /* Parent entries first */
    if ((*prev)->nelts > 0) {
        void *dst;

        dst = ngx_array_push_n(merged, (*prev)->nelts);
        if (dst == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(dst, (*prev)->elts, (*prev)->nelts * size);
    }

    /* Child entries after */
    if ((*conf)->nelts > 0) {
        void *dst;

        dst = ngx_array_push_n(merged, (*conf)->nelts);
        if (dst == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(dst, (*conf)->elts, (*conf)->nelts * size);
    }

    *conf = merged;

    return NGX_OK;
}


/*
 * Merge jwt_verify arrays with child-overrides-parent semantics.
 * If a child defines the same variable as a parent, the child entry
 * replaces the parent entry (no duplicate verification for the same token).
 */
static ngx_int_t
require_merge_jwt_verify(ngx_conf_t *cf, ngx_array_t **prev,
    ngx_array_t **conf)
{
    ngx_array_t *merged;
    ngx_auth_gate_jwt_verify_t *pv, *cv, *dst;
    ngx_uint_t i, j;
    ngx_flag_t overridden;

    if (*conf == NULL) {
        *conf = *prev;
        return NGX_OK;
    }

    if (*prev == NULL) {
        return NGX_OK;
    }

    merged = ngx_array_create(cf->pool,
                              (*prev)->nelts + (*conf)->nelts,
                              sizeof(ngx_auth_gate_jwt_verify_t));
    if (merged == NULL) {
        return NGX_ERROR;
    }

    /* Copy parent entries, skipping those overridden by child */
    pv = (*prev)->elts;
    cv = (*conf)->elts;

    for (i = 0; i < (*prev)->nelts; i++) {
        overridden = 0;

        for (j = 0; j < (*conf)->nelts; j++) {
            if (pv[i].variable_name.len == cv[j].variable_name.len
                && ngx_strncmp(pv[i].variable_name.data,
                               cv[j].variable_name.data,
                               pv[i].variable_name.len) == 0)
            {
                overridden = 1;
                break;
            }
        }

        if (!overridden) {
            dst = ngx_array_push(merged);
            if (dst == NULL) {
                return NGX_ERROR;
            }
            *dst = pv[i];
        }
    }

    /* Append all child entries */
    for (i = 0; i < (*conf)->nelts; i++) {
        dst = ngx_array_push(merged);
        if (dst == NULL) {
            return NGX_ERROR;
        }
        *dst = cv[i];
    }

    *conf = merged;

    return NGX_OK;
}


/*
 * Find a variable group by variable name.
 * Returns NULL if not found.
 */
static ngx_auth_gate_var_group_t *
require_find_group(ngx_array_t *groups, ngx_str_t *variable_name)
{
    ngx_uint_t i;
    ngx_auth_gate_var_group_t *g;

    g = groups->elts;

    for (i = 0; i < groups->nelts; i++) {
        if (g[i].variable_name.len == variable_name->len
            && ngx_strncmp(g[i].variable_name.data, variable_name->data,
                           variable_name->len) == 0)
        {
            return &g[i];
        }
    }

    return NULL;
}


/*
 * Merge two variable group arrays.
 * Parent groups first, child groups appended.
 * If both define the same variable, requirements are merged.
 */
static ngx_int_t
require_merge_groups(ngx_conf_t *cf, ngx_array_t **prev, ngx_array_t **conf)
{
    ngx_uint_t i, j;
    ngx_array_t *merged;
    ngx_auth_gate_var_group_t *pg, *cg, *mg;
    ngx_auth_gate_requirement_t *reqs;

    if (*conf == NULL) {
        *conf = *prev;
        return NGX_OK;
    }

    if (*prev == NULL) {
        return NGX_OK;
    }

    /* Both defined: merge parent + child groups */
    pg = (*prev)->elts;
    cg = (*conf)->elts;

    merged = ngx_array_create(cf->pool,
                              (*prev)->nelts + (*conf)->nelts,
                              sizeof(ngx_auth_gate_var_group_t));
    if (merged == NULL) {
        return NGX_ERROR;
    }

    /* Copy parent groups */
    for (i = 0; i < (*prev)->nelts; i++) {
        mg = ngx_array_push(merged);
        if (mg == NULL) {
            return NGX_ERROR;
        }

        mg->variable = pg[i].variable;
        mg->variable_name = pg[i].variable_name;

        mg->requirements = ngx_array_create(
            cf->pool, pg[i].requirements->nelts,
            sizeof(ngx_auth_gate_requirement_t));
        if (mg->requirements == NULL) {
            return NGX_ERROR;
        }

        reqs = pg[i].requirements->elts;

        for (j = 0; j < pg[i].requirements->nelts; j++) {
            ngx_auth_gate_requirement_t *dst;

            dst = ngx_array_push(mg->requirements);
            if (dst == NULL) {
                return NGX_ERROR;
            }

            *dst = reqs[j];
        }
    }

    /* Merge child groups: append to existing or create new */
    for (i = 0; i < (*conf)->nelts; i++) {
        mg = require_find_group(merged, &cg[i].variable_name);

        if (mg != NULL) {
            /* Same variable: append child requirements */
            reqs = cg[i].requirements->elts;

            for (j = 0; j < cg[i].requirements->nelts; j++) {
                ngx_auth_gate_requirement_t *dst;

                dst = ngx_array_push(mg->requirements);
                if (dst == NULL) {
                    return NGX_ERROR;
                }

                *dst = reqs[j];
            }

        } else {
            /* New variable: copy entire group */
            mg = ngx_array_push(merged);
            if (mg == NULL) {
                return NGX_ERROR;
            }

            /*
             * Shallow copy is intentional.  All members (variable,
             * variable_name, requirements array) are allocated from
             * cf->pool which outlives the merged configuration, so
             * the pointers remain valid for the lifetime of the
             * worker process.
             */
            *mg = cg[i];
        }
    }

    *conf = merged;

    return NGX_OK;
}


static void *
ngx_http_auth_gate_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_gate_loc_conf_t *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_gate_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    /* All arrays are NULL (no directives) by default via pcalloc */

    return lcf;
}


static char *
ngx_http_auth_gate_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_gate_loc_conf_t *prev = parent;
    ngx_http_auth_gate_loc_conf_t *conf = child;

    if (require_merge_array(cf, &prev->require_vars, &conf->require_vars,
                            sizeof(ngx_http_auth_gate_var_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (require_merge_array(cf, &prev->require_compare, &conf->require_compare,
                            sizeof(ngx_auth_gate_requirement_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (require_merge_groups(cf, &prev->require_json, &conf->require_json)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (require_merge_groups(cf, &prev->require_jwt, &conf->require_jwt)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (require_merge_jwt_verify(cf, &prev->require_jwt_verify,
                                 &conf->require_jwt_verify) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* Warn if auth_gate_jwt is used without auth_gate_jwt_verify */
    if (conf->require_jwt != NULL) {
        ngx_auth_gate_var_group_t *groups;
        ngx_uint_t i, j, found;

        groups = conf->require_jwt->elts;

        for (i = 0; i < conf->require_jwt->nelts; i++) {
            found = 0;

            if (conf->require_jwt_verify != NULL) {
                ngx_auth_gate_jwt_verify_t *verifies;

                verifies = conf->require_jwt_verify->elts;

                for (j = 0; j < conf->require_jwt_verify->nelts; j++) {
                    if (groups[i].variable_name.len ==
                        verifies[j].variable_name.len
                        && ngx_strncmp(groups[i].variable_name.data,
                                       verifies[j].variable_name.data,
                                       groups[i].variable_name.len) == 0)
                    {
                        found = 1;
                        break;
                    }
                }
            }

            if (!found) {
                ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
                                   "auth_gate_jwt: no signature verification "
                                   "is performed for \"%V\"",
                                   &groups[i].variable_name);
            }
        }
    }

    return NGX_CONF_OK;
}


/*
 * Variable handler: $auth_gate_epoch
 *
 * ngx_time() returns a cached time value that nginx updates once per
 * event loop iteration.  The precision is therefore limited to the
 * event loop cycle (typically millisecond-scale, but may lag under
 * heavy load).  This is acceptable for JWT exp/nbf comparisons.
 */
static ngx_int_t
require_variable_epoch(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char *p;

    /* NGX_TIME_T_LEN covers the maximum decimal representation of time_t */
    p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%T", ngx_time()) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


/*
 * auth_gate_jwt_verify directive handler
 *
 * Syntax: auth_gate_jwt_verify $variable jwks=<uri> [error=NNN]
 * Context: location
 */
static char *
ngx_http_auth_gate_conf_set_jwt_verify(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_gate_loc_conf_t *lcf = conf;

    ngx_str_t *values;
    ngx_uint_t i;
    ngx_auth_gate_jwt_verify_t *verify;
    ngx_http_compile_complex_value_t ccv;
    ngx_flag_t error_set;

    values = cf->args->elts;

    /* First arg: $variable */
    if (values[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gate_jwt_verify: "
                           "first argument must be a variable");
        return NGX_CONF_ERROR;
    }

    /* Second arg: jwks=<uri> */
    if (values[2].len < 6
        || ngx_strncmp(values[2].data, "jwks=", 5) != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gate_jwt_verify: "
                           "second argument must be jwks=<uri>");
        return NGX_CONF_ERROR;
    }

    {
        ngx_str_t uri;

        uri.data = values[2].data + 5;
        uri.len = values[2].len - 5;

        if (uri.len == 0 || uri.data[0] != '/') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_gate_jwt_verify: "
                               "jwks URI must start with '/': \"%V\"", &uri);
            return NGX_CONF_ERROR;
        }

        if (lcf->require_jwt_verify == NULL) {
            lcf->require_jwt_verify = ngx_array_create(
                cf->pool, 2, sizeof(ngx_auth_gate_jwt_verify_t));
            if (lcf->require_jwt_verify == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        /* Duplicate variable check */
        {
            ngx_auth_gate_jwt_verify_t *existing;
            ngx_uint_t j;

            existing = lcf->require_jwt_verify->elts;
            for (j = 0; j < lcf->require_jwt_verify->nelts; j++) {
                if (existing[j].variable_name.len == values[1].len
                    && ngx_strncmp(existing[j].variable_name.data,
                                   values[1].data, values[1].len) == 0)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "auth_gate_jwt_verify: "
                                       "duplicate variable \"%V\"",
                                       &values[1]);
                    return NGX_CONF_ERROR;
                }
            }
        }

        verify = ngx_array_push(lcf->require_jwt_verify);
        if (verify == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(verify, sizeof(ngx_auth_gate_jwt_verify_t));

        /* Compile variable */
        verify->variable = ngx_palloc(cf->pool,
                                      sizeof(ngx_http_complex_value_t));
        if (verify->variable == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &values[1];
        ccv.complex_value = verify->variable;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        verify->variable_name = values[1];
        verify->jwks_uri = uri;
    }

    /* Parse optional error=NNN */
    verify->error = NGX_HTTP_UNAUTHORIZED;
    error_set = 0;

    for (i = 3; i < cf->args->nelts; i++) {
        ngx_int_t rc;

        rc = require_parse_error(cf, &values[i], &verify->error);
        if (rc == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        if (rc == NGX_OK) {
            if (error_set) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "auth_gate_jwt_verify: duplicate "
                                   "error= specified, overriding "
                                   "with \"%V\"", &values[i]);
            }
            error_set = 1;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gate_jwt_verify: "
                           "unexpected argument \"%V\"", &values[i]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * Start JWT verify process by issuing JWKS subrequests
 *
 * Creates ctx, deduplicates URIs, and issues one subrequest per unique URI.
 * Returns NGX_AGAIN (subrequests issued) or error code.
 */
static ngx_int_t
jwt_verify_start(ngx_http_request_t *r,
    ngx_http_auth_gate_loc_conf_t *lcf)
{
    ngx_http_auth_gate_ctx_t *ctx;
    ngx_auth_gate_jwt_verify_t *verifies;
    ngx_uint_t i, j, unique_count;
    ngx_str_t *unique_uris;
    ngx_http_request_t *sr;
    ngx_http_post_subrequest_t *ps;

    verifies = lcf->require_jwt_verify->elts;

    /* Preflight: evaluate all token variables before issuing subrequests */
    for (i = 0; i < lcf->require_jwt_verify->nelts; i++) {
        ngx_str_t token_val;

        if (ngx_http_complex_value(r, verifies[i].variable, &token_val)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate_jwt_verify: failed to evaluate "
                          "variable '%V'", &verifies[i].variable_name);
            return verifies[i].error;
        }

        if (token_val.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate_jwt_verify: empty token for "
                          "variable '%V' (preflight)",
                          &verifies[i].variable_name);
            return verifies[i].error;
        }
    }

    /* Count unique URIs */
    unique_count = 0;

    /* Use temporary stack/pool storage for unique URI list */
    unique_uris = ngx_palloc(r->pool,
                             lcf->require_jwt_verify->nelts *
                             sizeof(ngx_str_t));
    if (unique_uris == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (i = 0; i < lcf->require_jwt_verify->nelts; i++) {
        ngx_flag_t found = 0;

        for (j = 0; j < unique_count; j++) {
            if (unique_uris[j].len == verifies[i].jwks_uri.len
                && ngx_strncmp(unique_uris[j].data,
                               verifies[i].jwks_uri.data,
                               verifies[i].jwks_uri.len) == 0)
            {
                found = 1;
                break;
            }
        }

        if (!found) {
            unique_uris[unique_count] = verifies[i].jwks_uri;
            unique_count++;
        }
    }

    /* Get or create context (preserve existing fields like dynamic_regex_count) */
    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_gate_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_gate_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_auth_gate_module);
    }

    /*
     * Config parse requires jwks_uri to start with '/', so unique_count
     * should never be 0 here.  Guard defensively to prevent re-entry.
     */
    if (unique_count == 0) {
        ctx->jwt_verify_started = 1;
        ctx->jwt_verify_done = 1;
        return NGX_OK;
    }

    ctx->jwks_results = ngx_pcalloc(r->pool,
                                    unique_count *
                                    sizeof(ngx_auth_gate_jwks_fetch_result_t));
    if (ctx->jwks_results == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->jwks_expected = unique_count;
    ctx->jwks_fetched = 0;
    ctx->jwt_verify_started = 1;
    ctx->jwt_verify_done = 0;

    for (i = 0; i < unique_count; i++) {
        ctx->jwks_results[i].jwks_uri = unique_uris[i];
    }

    /* Issue subrequests */
    for (i = 0; i < unique_count; i++) {
        ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
        if (ps == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ps->handler = jwks_post_subrequest_handler;
        ps->data = &ctx->jwks_results[i];

        if (ngx_http_subrequest(r, &unique_uris[i], NULL, &sr, ps,
                                NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate_jwt_verify: failed to create "
                          "subrequest for '%V'", &unique_uris[i]);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "auth_gate_jwt_verify: subrequest issued for '%V'",
                       &unique_uris[i]);
    }

    return NGX_AGAIN;
}


/*
 * Post-subrequest handler: save response body and status
 */
static ngx_int_t
jwks_post_subrequest_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_auth_gate_jwks_fetch_result_t *result = data;
    ngx_http_auth_gate_ctx_t *ctx;
    ngx_buf_t *buf;
    ngx_chain_t *cl;
    size_t total_size;

    ctx = ngx_http_get_module_ctx(r->parent, ngx_http_auth_gate_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    result->status = r->headers_out.status;
    result->done = 1;

    /* Reject encoded responses (gzip, br, zstd, etc.) */
    if (r->headers_out.content_encoding
        && r->headers_out.content_encoding->value.len > 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_gate_jwt_verify: JWKS response has "
                      "Content-Encoding '%V' for '%V'; "
                      "add 'proxy_set_header Accept-Encoding \"\"' "
                      "to the JWKS subrequest location",
                      &r->headers_out.content_encoding->value,
                      &result->jwks_uri);
        ctx->jwks_fetched++;
        return NGX_OK;
    }

    /* Collect response body from upstream buffer chain */
    if (r->upstream && r->upstream->buffer.pos) {
        /* Single buffer from upstream */
        buf = &r->upstream->buffer;
        total_size = buf->last - buf->pos;

        if (total_size > NGX_AUTH_GATE_MAX_JWKS_SIZE) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate_jwt_verify: JWKS response too large: "
                          "%uz for '%V'", total_size, &result->jwks_uri);
            ctx->jwks_fetched++;
            return NGX_OK;
        }

        if (total_size > 0) {
            result->body.data = ngx_pnalloc(r->parent->pool, total_size);
            if (result->body.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "auth_gate_jwt_verify: failed to allocate "
                              "JWKS body buffer for '%V'",
                              &result->jwks_uri);
                result->status = 0;
                ctx->jwks_fetched++;
                return NGX_OK;
            }
            ngx_memcpy(result->body.data, buf->pos, total_size);
            result->body.len = total_size;
        }
    } else if (r->out) {
        /* Buffer chain from subrequest */
        total_size = 0;
        for (cl = r->out; cl; cl = cl->next) {
            if (cl->buf) {
                total_size += cl->buf->last - cl->buf->pos;
            }
        }

        if (total_size > NGX_AUTH_GATE_MAX_JWKS_SIZE) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate_jwt_verify: JWKS response too large: "
                          "%uz for '%V'", total_size, &result->jwks_uri);
            ctx->jwks_fetched++;
            return NGX_OK;
        }

        if (total_size > 0) {
            u_char *p;

            result->body.data = ngx_pnalloc(r->parent->pool, total_size);
            if (result->body.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "auth_gate_jwt_verify: failed to allocate "
                              "JWKS body buffer for '%V'",
                              &result->jwks_uri);
                result->status = 0;
                ctx->jwks_fetched++;
                return NGX_OK;
            }

            p = result->body.data;
            for (cl = r->out; cl; cl = cl->next) {
                if (cl->buf) {
                    size_t len = cl->buf->last - cl->buf->pos;
                    p = ngx_cpymem(p, cl->buf->pos, len);
                }
            }

            result->body.len = total_size;
        }
    }

    ctx->jwks_fetched++;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth_gate_jwt_verify: JWKS fetched for '%V', "
                   "status=%i", &result->jwks_uri, result->status);

    return NGX_OK;
}


/*
 * Execute JWT signature verification after all JWKS have been fetched
 *
 * For each verify directive:
 * 1. Find the JWKS result matching the verify's URI
 * 2. Check HTTP status (must be 200)
 * 3. Parse JWKS
 * 4. Evaluate variable to get JWT token
 * 5. Verify signature
 */
static ngx_int_t
jwt_verify_execute(ngx_http_request_t *r,
    ngx_http_auth_gate_loc_conf_t *lcf, ngx_http_auth_gate_ctx_t *ctx)
{
    ngx_auth_gate_jwt_verify_t *verifies;
    ngx_auth_gate_jwks_fetch_result_t *result;
    ngx_auth_gate_jwks_keyset_t *keyset;
    ngx_uint_t i, j;
    ngx_str_t token_val;
    ngx_int_t rc;

    verifies = lcf->require_jwt_verify->elts;

    for (i = 0; i < lcf->require_jwt_verify->nelts; i++) {
        /* Find matching JWKS result */
        result = NULL;

        for (j = 0; j < ctx->jwks_expected; j++) {
            if (ctx->jwks_results[j].jwks_uri.len == verifies[i].jwks_uri.len
                && ngx_strncmp(ctx->jwks_results[j].jwks_uri.data,
                               verifies[i].jwks_uri.data,
                               verifies[i].jwks_uri.len) == 0)
            {
                result = &ctx->jwks_results[j];
                break;
            }
        }

        if (result == NULL || !result->done) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate_jwt_verify: JWKS result not found "
                          "for '%V'", &verifies[i].jwks_uri);
            return verifies[i].error;
        }

        /* Check HTTP status */
        if (result->status != NGX_HTTP_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate_jwt_verify: JWKS fetch returned "
                          "status %i for '%V'",
                          result->status, &verifies[i].jwks_uri);
            return verifies[i].error;
        }

        /* Check body */
        if (result->body.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate_jwt_verify: empty JWKS response "
                          "for '%V'", &verifies[i].jwks_uri);
            return verifies[i].error;
        }

        /* Parse JWKS (cache in result to avoid re-parsing for same URI) */
        if (result->keyset != NULL) {
            keyset = result->keyset;
        } else {
            keyset = ngx_auth_gate_jwks_parse(r->pool, &result->body,
                                              r->connection->log);
            if (keyset == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "auth_gate_jwt_verify: JWKS parse failed "
                              "for '%V'", &verifies[i].jwks_uri);
                return verifies[i].error;
            }
            result->keyset = keyset;
        }

        /* Evaluate variable to get JWT token */
        if (ngx_http_complex_value(r, verifies[i].variable, &token_val)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate_jwt_verify: failed to evaluate "
                          "variable '%V'", &verifies[i].variable_name);
            return verifies[i].error;
        }

        if (token_val.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate_jwt_verify: empty token for "
                          "variable '%V'", &verifies[i].variable_name);
            return verifies[i].error;
        }

        /* Verify signature */
        rc = ngx_auth_gate_jws_verify(&token_val, keyset, r->pool,
                                      r->connection->log);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_gate_jwt_verify: signature verification "
                          "failed for variable '%V'",
                          &verifies[i].variable_name);
            return verifies[i].error;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "auth_gate_jwt_verify: signature verified "
                       "for variable '%V'", &verifies[i].variable_name);
    }

    return NGX_OK;
}


/* Module initialization: register ACCESS phase handler and variables */
static ngx_int_t
ngx_http_auth_gate_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_variable_t *var, *v;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_gate_access_handler;

    /* Register variables */
    for (v = require_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}
