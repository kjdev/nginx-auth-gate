/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_HTTP_AUTH_GATE_MODULE_H_INCLUDED_
#define _NGX_HTTP_AUTH_GATE_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_auth_gate_field.h"
#include "ngx_auth_gate_operator.h"
#include "ngx_auth_gate_jwks.h"

/** auth_gate boolean check requirement (one auth_gate line) */
typedef struct {
    ngx_array_t *values;                    /* ngx_http_complex_value_t */
    ngx_int_t    error;                     /* error status code */
} ngx_http_auth_gate_var_t;

/** comparison requirement (auth_gate/auth_gate_json/auth_gate_jwt) */
typedef struct {
    ngx_http_complex_value_t   *variable;        /* target variable ($var) */
    ngx_auth_gate_field_path_t  field;        /* parsed field path */
    ngx_auth_gate_operator_pt   operator;     /* operator handler */
    ngx_str_t                   operator_name;    /* operator name (for log) */
    ngx_flag_t                  negate;          /* ! prefix negation */
    ngx_http_complex_value_t   *expected;        /* expected value */
    ngx_flag_t                  expected_json;    /* json= prefix flag */
    ngx_int_t                   error;           /* error status code */
#if (NGX_PCRE)
    ngx_regex_t                *compiled_regex;    /* precompiled regex */
#endif
} ngx_auth_gate_requirement_t;

/** variable group for json/jwt (same variable parsed once) */
typedef struct {
    ngx_http_complex_value_t *variable;       /* compiled variable */
    ngx_str_t                 variable_name;  /* variable name (grouping) */
    ngx_array_t              *requirements; /* ngx_auth_gate_requirement_t */
} ngx_auth_gate_var_group_t;

/** JWT verify directive configuration */
typedef struct {
    ngx_http_complex_value_t *variable;       /* $token */
    ngx_str_t                 variable_name;  /* variable name (dup check) */
    ngx_str_t                 jwks_uri;       /* /jwks_uri */
    ngx_int_t                 error;          /* error status code */
} ngx_auth_gate_jwt_verify_t;

/** JWKS fetch result (per unique URI) */
typedef struct {
    ngx_str_t                    jwks_uri; /* which URI this result belongs to */
    ngx_str_t                    body; /* response body */
    ngx_int_t                    status; /* HTTP status */
    ngx_auth_gate_jwks_keyset_t *keyset;  /* cached parsed keyset (avoid re-parsing) */
    unsigned                     done:1; /* fetch completed */
} ngx_auth_gate_jwks_fetch_result_t;

/** auth_gate module location configuration */
typedef struct {
    ngx_array_t *require_vars;        /* ngx_http_auth_gate_var_t */
    ngx_array_t *require_compare;     /* ngx_auth_gate_requirement_t */
    ngx_array_t *require_json;        /* ngx_auth_gate_var_group_t */
    ngx_array_t *require_jwt;         /* ngx_auth_gate_var_group_t */
    ngx_array_t *require_jwt_verify;  /* ngx_auth_gate_jwt_verify_t */
} ngx_http_auth_gate_loc_conf_t;

/** per-request context for runtime limits and subrequest tracking */
typedef struct {
    ngx_uint_t                         dynamic_regex_count; /* dynamic PCRE compilations */

    /* JWT verify subrequest management */
    ngx_auth_gate_jwks_fetch_result_t *jwks_results;   /* result array */
    ngx_uint_t                         jwks_expected;   /* unique URI count */
    ngx_uint_t                         jwks_fetched;    /* completed count */
    unsigned                           jwt_verify_started:1;
    unsigned                           jwt_verify_done:1;
} ngx_http_auth_gate_ctx_t;

extern ngx_module_t ngx_http_auth_gate_module;

#endif /* _NGX_HTTP_AUTH_GATE_MODULE_H_INCLUDED_ */
