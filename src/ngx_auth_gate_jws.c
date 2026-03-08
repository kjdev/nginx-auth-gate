/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * JWT signature verification (JWS) for auth_gate module
 *
 * Verifies JWT signatures using OpenSSL EVP API with support for
 * RSA (RS256/384/512, PS256/384/512), ECDSA (ES256/384/512, ES256K),
 * and EdDSA (Ed25519, Ed448).
 *
 * Based on ngx_oidc_jwt.c signature verification from the OIDC module.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>

#include "ngx_auth_gate_jws.h"
#include "ngx_auth_gate_json.h"
#include "ngx_auth_gate_jwt.h"


/* Allowed JWT signing algorithms (whitelist) */
static const char *jws_allowed_algs[] = {
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
    "ES256K",
    "EdDSA",
    NULL
};


static void
jws_get_openssl_error(char *buf, size_t buf_len)
{
    unsigned long err = ERR_get_error();
    u_char *p;

    if (err != 0) {
        ERR_error_string_n(err, buf, buf_len);
    } else {
        p = ngx_snprintf((u_char *) buf, buf_len - 1,
                         "no error information");
        *p = '\0';
    }
}


static ngx_int_t
jws_validate_algorithm(ngx_str_t *alg, ngx_log_t *log)
{
    size_t i;

    if (alg == NULL || alg->len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: JWT algorithm is missing");
        return NGX_ERROR;
    }

    /* Explicit rejection of "none" */
    if (alg->len == 4
        && ngx_strncmp(alg->data, "none", 4) == 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: algorithm 'none' is not allowed");
        return NGX_ERROR;
    }

    /* Explicit rejection of HMAC algorithms */
    if (alg->len >= 2
        && alg->data[0] == 'H' && alg->data[1] == 'S')
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: HMAC algorithm '%V' is not allowed",
                      alg);
        return NGX_ERROR;
    }

    /* Whitelist check */
    for (i = 0; jws_allowed_algs[i] != NULL; i++) {
        size_t len = ngx_strlen(jws_allowed_algs[i]);
        if (alg->len == len
            && ngx_strncmp(alg->data, jws_allowed_algs[i], len) == 0)
        {
            return NGX_OK;
        }
    }

    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "auth_gate_jws: algorithm '%V' is not in whitelist", alg);
    return NGX_ERROR;
}


/*
 * Map JWT algorithm to OpenSSL EVP_MD
 *
 * Returns NULL for EdDSA (no separate digest) and unsupported algorithms.
 */
static const EVP_MD *
jws_get_md(ngx_str_t *alg)
{
    u_char *suffix;

    if (alg == NULL || alg->len < 4) {
        return NULL;
    }

    /* EdDSA: no separate digest */
    if (alg->len == 5
        && ngx_strncmp(alg->data, "EdDSA", 5) == 0)
    {
        return NULL;
    }

    /* ES256K: suffix is "56K", handle before suffix-based matching */
    if (alg->len == 6
        && ngx_strncmp(alg->data, "ES256K", 6) == 0)
    {
        return EVP_sha256();
    }

    /* Standard RS/PS/ES algorithms: hash size from last 3 characters */
    suffix = alg->data + alg->len - 3;

    if (ngx_strncmp(suffix, "256", 3) == 0) {
        return EVP_sha256();
    }

    if (ngx_strncmp(suffix, "384", 3) == 0) {
        return EVP_sha384();
    }

    if (ngx_strncmp(suffix, "512", 3) == 0) {
        return EVP_sha512();
    }

    return NULL;
}


static ngx_int_t
jws_verify_rsa(u_char *hp_data, size_t hp_len,
    u_char *sig_data, size_t sig_len,
    EVP_PKEY *pkey, ngx_str_t *alg, ngx_log_t *log)
{
    const EVP_MD *md;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    int rc;
    char err_buf[256];

    md = jws_get_md(alg);
    if (md == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: unsupported digest for RSA alg '%V'",
                      alg);
        return NGX_ERROR;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        ERR_clear_error();
        return NGX_ERROR;
    }

    if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, md, NULL, pkey) != 1) {
        jws_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: EVP_DigestVerifyInit failed: %s",
                      err_buf);
        ERR_clear_error();
        EVP_MD_CTX_free(mdctx);
        return NGX_ERROR;
    }

    /* Handle PSS padding */
    if (alg->len >= 2
        && alg->data[0] == 'P' && alg->data[1] == 'S')
    {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING)
            != 1)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "auth_gate_jws: failed to set RSA PSS padding");
            ERR_clear_error();
            EVP_MD_CTX_free(mdctx);
            return NGX_ERROR;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST)
            != 1)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "auth_gate_jws: failed to set RSA PSS saltlen");
            ERR_clear_error();
            EVP_MD_CTX_free(mdctx);
            return NGX_ERROR;
        }
    }

    rc = EVP_DigestVerify(mdctx, sig_data, sig_len, hp_data, hp_len);
    EVP_MD_CTX_free(mdctx);

    if (rc == 1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "auth_gate_jws: RSA signature verification succeeded");
        return NGX_OK;
    }

    jws_get_openssl_error(err_buf, sizeof(err_buf));
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "auth_gate_jws: RSA signature mismatch: %s", err_buf);
    ERR_clear_error();
    return NGX_DECLINED;
}


static ngx_int_t
jws_verify_ec(u_char *hp_data, size_t hp_len,
    u_char *sig_data, size_t sig_len,
    EVP_PKEY *pkey, ngx_str_t *alg, ngx_log_t *log)
{
    const EVP_MD *md;
    EVP_MD_CTX *mdctx = NULL;
    ECDSA_SIG *ec_sig = NULL;
    unsigned char *der_sig = NULL;
    BIGNUM *bn_r = NULL, *bn_s = NULL;
    int key_bits, coord_size, der_len, rc;
    ngx_int_t result = NGX_ERROR;
    char err_buf[256];

    md = jws_get_md(alg);
    if (md == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: unsupported digest for EC alg '%V'",
                      alg);
        return NGX_ERROR;
    }

    key_bits = EVP_PKEY_bits(pkey);
    if (key_bits <= 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: invalid key size: %d", key_bits);
        return NGX_ERROR;
    }
    coord_size = (key_bits + 7) / 8;

    if (sig_len != (size_t) (coord_size * 2)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: invalid ECDSA signature length: "
                      "expected %d, got %uz", coord_size * 2, sig_len);
        return NGX_ERROR;
    }

    /* Convert R||S to DER format */
    bn_r = BN_bin2bn(sig_data, coord_size, NULL);
    if (bn_r == NULL) {
        goto cleanup;
    }

    bn_s = BN_bin2bn(sig_data + coord_size, coord_size, NULL);
    if (bn_s == NULL) {
        goto cleanup;
    }

    ec_sig = ECDSA_SIG_new();
    if (ec_sig == NULL) {
        goto cleanup;
    }

    /* ECDSA_SIG_set0 takes ownership of bn_r and bn_s on success */
    if (!ECDSA_SIG_set0(ec_sig, bn_r, bn_s)) {
        goto cleanup;
    }
    bn_r = NULL;
    bn_s = NULL;

    der_len = i2d_ECDSA_SIG(ec_sig, &der_sig);
    if (der_len <= 0 || der_sig == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: failed to convert ECDSA_SIG to DER");
        goto cleanup;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) != 1) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: EVP_DigestVerifyInit failed for ECDSA");
        goto cleanup;
    }

    rc = EVP_DigestVerify(mdctx, der_sig, der_len, hp_data, hp_len);

    if (rc == 1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "auth_gate_jws: ECDSA signature verification "
                       "succeeded");
        result = NGX_OK;
    } else {
        jws_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "auth_gate_jws: ECDSA signature mismatch: %s",
                       err_buf);
        ERR_clear_error();
        result = NGX_DECLINED;
    }

cleanup:
    if (result == NGX_ERROR) {
        ERR_clear_error();
    }

    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }
    if (der_sig != NULL) {
        OPENSSL_free(der_sig);
    }
    if (ec_sig != NULL) {
        ECDSA_SIG_free(ec_sig);
    }
    if (bn_r != NULL) {
        BN_free(bn_r);
    }
    if (bn_s != NULL) {
        BN_free(bn_s);
    }

    return result;
}


static ngx_int_t
jws_verify_eddsa(u_char *hp_data, size_t hp_len,
    u_char *sig_data, size_t sig_len,
    EVP_PKEY *pkey, ngx_log_t *log)
{
    EVP_MD_CTX *mdctx;
    int key_id, rc;
    char err_buf[256];

    key_id = EVP_PKEY_id(pkey);
    if (key_id != EVP_PKEY_ED25519 && key_id != EVP_PKEY_ED448) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: unsupported OKP key type: %d", key_id);
        return NGX_ERROR;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        ERR_clear_error();
        return NGX_ERROR;
    }

    /* EdDSA uses NULL as the digest */
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) != 1) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: EVP_DigestVerifyInit failed for EdDSA");
        ERR_clear_error();
        EVP_MD_CTX_free(mdctx);
        return NGX_ERROR;
    }

    rc = EVP_DigestVerify(mdctx, sig_data, sig_len, hp_data, hp_len);
    EVP_MD_CTX_free(mdctx);

    if (rc == 1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "auth_gate_jws: EdDSA signature verification "
                       "succeeded");
        return NGX_OK;
    }

    jws_get_openssl_error(err_buf, sizeof(err_buf));
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "auth_gate_jws: EdDSA signature mismatch: %s", err_buf);
    ERR_clear_error();
    return NGX_DECLINED;
}


ngx_int_t
ngx_auth_gate_jws_verify(ngx_str_t *token,
    ngx_auth_gate_jwks_keyset_t *keyset, ngx_pool_t *pool, ngx_log_t *log)
{
    u_char *dot1, *dot2;
    ngx_str_t header_b64, sig_b64, sig_decoded;
    ngx_auth_gate_json_t *header_json;
    ngx_str_t alg, kid;
    size_t hp_len;
    ngx_auth_gate_jwks_key_t *keys;
    ngx_uint_t i, tried;
    ngx_int_t rc;

    if (token == NULL || token->len == 0 || keyset == NULL
        || keyset->keys == NULL || keyset->keys->nelts == 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: invalid arguments for verification");
        return NGX_ERROR;
    }

    if (token->len > NGX_AUTH_GATE_MAX_JWT_LENGTH) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: token too large: %uz", token->len);
        return NGX_ERROR;
    }

    ERR_clear_error();

    /* Parse JWT structure: header.payload.signature */
    dot1 = ngx_strlchr(token->data, token->data + token->len, '.');
    if (dot1 == NULL || dot1 == token->data) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: invalid JWT format");
        return NGX_ERROR;
    }

    dot2 = ngx_strlchr(dot1 + 1, token->data + token->len, '.');
    if (dot2 == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: invalid JWT format (missing signature)");
        return NGX_ERROR;
    }

    /* Reject extra segments (JWE) */
    if (ngx_strlchr(dot2 + 1, token->data + token->len, '.') != NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: JWT has more than 3 segments");
        return NGX_ERROR;
    }

    /* Decode header */
    header_b64.data = token->data;
    header_b64.len = dot1 - token->data;

    header_json = ngx_auth_gate_jwt_decode_header(&header_b64, pool);
    if (header_json == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: failed to decode JWT header");
        return NGX_ERROR;
    }

    /* Extract alg */
    {
        ngx_str_t alg_key, alg_tmp;
        ngx_auth_gate_json_t *alg_val;

        ngx_str_set(&alg_key, "alg");
        alg_val = ngx_auth_gate_json_object_get(header_json, &alg_key);

        if (alg_val == NULL
            || ngx_auth_gate_json_string(alg_val, &alg_tmp) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "auth_gate_jws: missing 'alg' in JWT header");
            ngx_auth_gate_json_free(header_json);
            return NGX_ERROR;
        }

        /* Copy to pool before freeing header_json */
        alg.data = ngx_pstrdup(pool, &alg_tmp);
        alg.len = alg_tmp.len;
        if (alg.data == NULL) {
            ngx_auth_gate_json_free(header_json);
            return NGX_ERROR;
        }
    }

    /* Validate algorithm */
    if (jws_validate_algorithm(&alg, log) != NGX_OK) {
        ngx_auth_gate_json_free(header_json);
        return NGX_ERROR;
    }

    /* Extract kid (optional) */
    ngx_str_null(&kid);
    {
        ngx_str_t kid_key, kid_tmp;
        ngx_auth_gate_json_t *kid_val;

        ngx_str_set(&kid_key, "kid");
        kid_val = ngx_auth_gate_json_object_get(header_json, &kid_key);

        if (kid_val != NULL
            && ngx_auth_gate_json_string(kid_val, &kid_tmp) == NGX_OK)
        {
            kid.data = ngx_pstrdup(pool, &kid_tmp);
            if (kid.data != NULL) {
                kid.len = kid_tmp.len;
            }
        }
    }

    ngx_auth_gate_json_free(header_json);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "auth_gate_jws: JWT header alg='%V', kid='%V'",
                   &alg, &kid);

    /* header.payload is the signing input (raw base64url, not decoded) */
    hp_len = dot2 - token->data;

    /* Decode signature */
    sig_b64.data = dot2 + 1;
    sig_b64.len = token->data + token->len - (dot2 + 1);

    sig_decoded.len = ngx_base64_decoded_length(sig_b64.len);
    sig_decoded.data = ngx_pnalloc(pool, sig_decoded.len);
    if (sig_decoded.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64url(&sig_decoded, &sig_b64) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jws: failed to decode JWT signature");
        return NGX_ERROR;
    }

    /* Try each key from the keyset */
    keys = keyset->keys->elts;
    tried = 0;

    for (i = 0; i < keyset->keys->nelts; i++) {
        /* kid matching */
        if (kid.len > 0) {
            if (keys[i].kid.len == 0
                || kid.len != keys[i].kid.len
                || ngx_strncmp(kid.data, keys[i].kid.data, kid.len) != 0)
            {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                               "auth_gate_jws: kid mismatch: JWT='%V', "
                               "key='%V'", &kid, &keys[i].kid);
                continue;
            }
        }

        /* alg matching (if key has alg) */
        if (keys[i].alg.len > 0) {
            if (alg.len != keys[i].alg.len
                || ngx_strncmp(alg.data, keys[i].alg.data, alg.len) != 0)
            {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                               "auth_gate_jws: alg mismatch: JWT='%V', "
                               "key='%V'", &alg, &keys[i].alg);
                continue;
            }
        }

        /* kty compatibility check */
        if (keys[i].kty == NGX_AUTH_GATE_JWK_RSA) {
            if (alg.len < 2
                || (ngx_strncmp(alg.data, "RS", 2) != 0
                    && ngx_strncmp(alg.data, "PS", 2) != 0))
            {
                continue;
            }
        } else if (keys[i].kty == NGX_AUTH_GATE_JWK_EC) {
            if (alg.len < 2
                || ngx_strncmp(alg.data, "ES", 2) != 0)
            {
                continue;
            }

            /* Validate alg-curve compatibility */
            if (keys[i].crv.len > 0) {
                ngx_flag_t curve_match = 0;

                if (alg.len == 5
                    && ngx_strncmp(alg.data, "ES256", 5) == 0
                    && keys[i].crv.len == 5
                    && ngx_strncmp(keys[i].crv.data, "P-256", 5) == 0)
                {
                    curve_match = 1;
                } else if (alg.len == 5
                           && ngx_strncmp(alg.data, "ES384", 5) == 0
                           && keys[i].crv.len == 5
                           && ngx_strncmp(keys[i].crv.data, "P-384", 5) == 0)
                {
                    curve_match = 1;
                } else if (alg.len == 5
                           && ngx_strncmp(alg.data, "ES512", 5) == 0
                           && keys[i].crv.len == 5
                           && ngx_strncmp(keys[i].crv.data, "P-521", 5) == 0)
                {
                    curve_match = 1;
                } else if (alg.len == 6
                           && ngx_strncmp(alg.data, "ES256K", 6) == 0
                           && keys[i].crv.len == 9
                           && ngx_strncmp(keys[i].crv.data, "secp256k1", 9)
                           == 0)
                {
                    curve_match = 1;
                }

                if (!curve_match) {
                    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
                                   "auth_gate_jws: alg-curve mismatch: "
                                   "alg='%V', crv='%V', key #%ui",
                                   &alg, &keys[i].crv, i);
                    continue;
                }
            }
        } else if (keys[i].kty == NGX_AUTH_GATE_JWK_OKP) {
            if (alg.len != 5
                || ngx_strncmp(alg.data, "EdDSA", 5) != 0)
            {
                continue;
            }
        }

        if (keys[i].pkey == NULL) {
            continue;
        }

        tried++;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
                       "auth_gate_jws: trying key #%ui: kty=%d, kid='%V'",
                       i, keys[i].kty, &keys[i].kid);

        /* Verify signature based on key type */
        rc = NGX_ERROR;

        if (keys[i].kty == NGX_AUTH_GATE_JWK_RSA) {
            rc = jws_verify_rsa(token->data, hp_len,
                                sig_decoded.data, sig_decoded.len,
                                keys[i].pkey, &alg, log);
        } else if (keys[i].kty == NGX_AUTH_GATE_JWK_EC) {
            rc = jws_verify_ec(token->data, hp_len,
                               sig_decoded.data, sig_decoded.len,
                               keys[i].pkey, &alg, log);
        } else if (keys[i].kty == NGX_AUTH_GATE_JWK_OKP) {
            rc = jws_verify_eddsa(token->data, hp_len,
                                  sig_decoded.data, sig_decoded.len,
                                  keys[i].pkey, log);
        }

        if (rc == NGX_OK) {
            return NGX_OK;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        /* NGX_DECLINED: try next key */
    }

    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "auth_gate_jws: signature verification failed "
                  "(tried %ui of %ui keys)", tried, keyset->keys->nelts);
    return NGX_DECLINED;
}
