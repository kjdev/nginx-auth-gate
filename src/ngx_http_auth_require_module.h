/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_HTTP_AUTH_REQUIRE_MODULE_H_INCLUDED_
#define _NGX_HTTP_AUTH_REQUIRE_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_auth_require_field.h"
#include "ngx_auth_require_operator.h"

/** auth_require boolean check requirement (one auth_require line) */
typedef struct {
    ngx_array_t *values;                    /* ngx_http_complex_value_t */
    ngx_int_t    error;                     /* error status code */
} ngx_http_auth_require_var_t;

/** comparison requirement (auth_require/auth_require_json/auth_require_jwt) */
typedef struct {
    ngx_http_complex_value_t      *variable;     /* target variable ($var) */
    ngx_auth_require_field_path_t  field;        /* parsed field path */
    ngx_auth_require_operator_pt   operator;     /* operator handler */
    ngx_str_t                      operator_name; /* operator name (for log) */
    ngx_flag_t                     negate;       /* ! prefix negation */
    ngx_http_complex_value_t      *expected;     /* expected value */
    ngx_flag_t                     expected_json; /* json= prefix flag */
    ngx_int_t                      error;        /* error status code */
#if (NGX_PCRE)
    ngx_regex_t                   *compiled_regex; /* precompiled regex */
#endif
} ngx_auth_require_requirement_t;

/** variable group for json/jwt (same variable parsed once) */
typedef struct {
    ngx_http_complex_value_t *variable;       /* compiled variable */
    ngx_str_t                 variable_name;  /* variable name (grouping) */
    ngx_array_t              *requirements; /* ngx_auth_require_requirement_t */
} ngx_auth_require_var_group_t;

/** auth_require module location configuration */
typedef struct {
    ngx_array_t *require_vars;      /* ngx_http_auth_require_var_t */
    ngx_array_t *require_compare;   /* ngx_auth_require_requirement_t */
    ngx_array_t *require_json;      /* ngx_auth_require_var_group_t */
    ngx_array_t *require_jwt;       /* ngx_auth_require_var_group_t */
} ngx_http_auth_require_loc_conf_t;

/** per-request context for runtime limits */
typedef struct {
    ngx_uint_t  dynamic_regex_count;    /* dynamic PCRE compilations */
} ngx_http_auth_require_ctx_t;

extern ngx_module_t ngx_http_auth_require_module;

#endif /* _NGX_HTTP_AUTH_REQUIRE_MODULE_H_INCLUDED_ */
