/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_AUTH_REQUIRE_OPERATOR_H_INCLUDED_
#define _NGX_AUTH_REQUIRE_OPERATOR_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_auth_require_json.h"

/**
 * Operator handler function pointer type
 *
 * @return NGX_OK       condition satisfied
 * @return NGX_DECLINED condition not satisfied (valid comparison)
 * @return NGX_ERROR    internal error (type mismatch, resource limit, etc.)
 */
typedef ngx_int_t (*ngx_auth_require_operator_pt)(
    ngx_auth_require_json_t *actual,
    ngx_auth_require_json_t *expected,
    ngx_pool_t *pool);

/**
 * Find an operator by name
 *
 * If name starts with "!", strips it and sets negate=1,
 * then looks up the remaining name in the operator table.
 *
 * @param[in]  name    operator name (e.g., "eq", "!in", "any")
 * @param[out] op      operator handler
 * @param[out] negate  negation flag
 *
 * @return NGX_OK on success, NGX_DECLINED if not found
 */
ngx_int_t ngx_auth_require_operator_find(ngx_str_t *name,
    ngx_auth_require_operator_pt *op, ngx_flag_t *negate);

#if (NGX_PCRE)
/**
 * Execute a regex match with match_limit / depth_limit for ReDoS protection
 *
 * @param[in]  re  compiled regex (ngx_regex_t *)
 * @param[in]  s   subject string
 *
 * @return NGX_OK on match, NGX_DECLINED on no match, NGX_ERROR on limit exceeded
 */
ngx_int_t ngx_auth_require_regex_exec_limited(ngx_regex_t *re,
    ngx_str_t *s, ngx_log_t *log);
#endif

#endif /* _NGX_AUTH_REQUIRE_OPERATOR_H_INCLUDED_ */
