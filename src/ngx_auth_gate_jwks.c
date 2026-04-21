/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * JWKS (JSON Web Key Set) parser for auth_gate module
 *
 * Converts JWK entries to OpenSSL EVP_PKEY objects using the
 * OpenSSL 3.0 EVP_PKEY_fromdata API.
 *
 * Based on ngx_oidc_jwks.c from the OIDC module (simplified, no SHM cache).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "auth_gate_jwks requires OpenSSL 3.0 or later"
#endif

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "ngx_auth_gate_jwks.h"
#include "nxe_json.h"


static void
jwks_get_openssl_error(char *buf, size_t buf_len)
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


static void
jwks_keyset_cleanup(void *data)
{
    ngx_auth_gate_jwks_keyset_t *keyset;
    ngx_auth_gate_jwks_key_t *keys;
    ngx_uint_t i;

    keyset = data;
    if (keyset == NULL || keyset->keys == NULL) {
        return;
    }

    keys = keyset->keys->elts;
    for (i = 0; i < keyset->keys->nelts; i++) {
        if (keys[i].pkey != NULL) {
            EVP_PKEY_free(keys[i].pkey);
            keys[i].pkey = NULL;
        }
    }
}


/*
 * Helper: get a string field from a JSON object by C string key
 */
static ngx_int_t
jwks_get_string_field(nxe_json_t *obj, const char *key_cstr,
    ngx_str_t *value)
{
    nxe_json_t *field;

    field = nxe_json_object_get(obj, key_cstr);
    if (field == NULL || !nxe_json_is_string(field)) {
        return NGX_ERROR;
    }

    return nxe_json_string(field, value);
}


/*
 * Helper: check if a JSON object has a string field with specific value
 */
static ngx_flag_t
jwks_has_string_value(nxe_json_t *obj, const char *key_cstr,
    const char *expected)
{
    ngx_str_t value;

    if (jwks_get_string_field(obj, key_cstr, &value) != NGX_OK) {
        return 0;
    }

    return (value.len == ngx_strlen(expected)
            && ngx_strncmp(value.data, expected, value.len) == 0);
}


static EVP_PKEY *
jwks_create_rsa_key(nxe_json_t *jwk, ngx_pool_t *pool,
    ngx_log_t *log)
{
    ngx_str_t n_str, e_str, n_decoded, e_decoded;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n_bn = NULL, *e_bn = NULL;
    char err_buf[256];

    ERR_clear_error();

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                   "auth_gate_jwks: creating RSA public key from JWK");

    if (jwks_get_string_field(jwk, "n", &n_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: missing or invalid 'n' parameter");
        return NULL;
    }

    if (jwks_get_string_field(jwk, "e", &e_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: missing or invalid 'e' parameter");
        return NULL;
    }

    /* Decode Base64url-encoded parameters */
    n_decoded.len = ngx_base64_decoded_length(n_str.len);
    n_decoded.data = ngx_pnalloc(pool, n_decoded.len);
    if (n_decoded.data == NULL) {
        return NULL;
    }
    if (ngx_decode_base64url(&n_decoded, &n_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: failed to decode 'n' parameter");
        return NULL;
    }

    e_decoded.len = ngx_base64_decoded_length(e_str.len);
    e_decoded.data = ngx_pnalloc(pool, e_decoded.len);
    if (e_decoded.data == NULL) {
        return NULL;
    }
    if (ngx_decode_base64url(&e_decoded, &e_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: failed to decode 'e' parameter");
        return NULL;
    }

    /* Validate minimum RSA key length (2048 bits = 256 bytes) */
    if (n_decoded.len < 256) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: RSA modulus too short: %uz bytes "
                      "(minimum 256 bytes / 2048 bits)", n_decoded.len);
        return NULL;
    }

    /* Validate RSA public exponent: must be odd and >= 3 */
    if (e_decoded.len == 0
        || (e_decoded.data[e_decoded.len - 1] & 1) == 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: RSA exponent must be an odd integer");
        return NULL;
    }

    if (e_decoded.len == 1 && e_decoded.data[0] < 3) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: RSA exponent too small "
                      "(minimum value 3)");
        return NULL;
    }

    /* Convert to BIGNUM */
    n_bn = BN_bin2bn(n_decoded.data, n_decoded.len, NULL);
    if (n_bn == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: BN_bin2bn failed for 'n': %s", err_buf);
        goto cleanup;
    }

    e_bn = BN_bin2bn(e_decoded.data, e_decoded.len, NULL);
    if (e_bn == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: BN_bin2bn failed for 'e': %s", err_buf);
        goto cleanup;
    }

    /* Build OpenSSL 3.0 parameters */
    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: OSSL_PARAM_BLD_new failed: %s",
                      err_buf);
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n_bn)
        || !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e_bn))
    {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: OSSL_PARAM_BLD_push_BN failed: %s",
                      err_buf);
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: OSSL_PARAM_BLD_to_param failed: %s",
                      err_buf);
        goto cleanup;
    }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (pctx == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: EVP_PKEY_CTX_new_from_name failed: %s",
                      err_buf);
        goto cleanup;
    }

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: EVP_PKEY_fromdata_init failed: %s",
                      err_buf);
        goto cleanup;
    }

    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: EVP_PKEY_fromdata failed: %s", err_buf);
        goto cleanup;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                   "auth_gate_jwks: RSA public key created successfully");

cleanup:
    if (n_bn != NULL) {
        BN_free(n_bn);
    }
    if (e_bn != NULL) {
        BN_free(e_bn);
    }
    if (param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if (params != NULL) {
        OSSL_PARAM_free(params);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }

    return pkey;
}


static EVP_PKEY *
jwks_create_ec_key(nxe_json_t *jwk, ngx_pool_t *pool,
    ngx_log_t *log)
{
    ngx_str_t crv_str, x_str, y_str, x_decoded, y_decoded;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    const char *group_name = NULL;
    u_char *pub_key = NULL;
    size_t pub_key_len;
    char err_buf[256];

    ERR_clear_error();

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                   "auth_gate_jwks: creating EC public key from JWK");

    if (jwks_get_string_field(jwk, "crv", &crv_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: missing or invalid 'crv' parameter");
        return NULL;
    }

    if (jwks_get_string_field(jwk, "x", &x_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: missing or invalid 'x' parameter");
        return NULL;
    }

    if (jwks_get_string_field(jwk, "y", &y_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: missing or invalid 'y' parameter");
        return NULL;
    }

    /* Map JWK curve name to OpenSSL group name */
    if (crv_str.len == 5
        && ngx_strncmp(crv_str.data, "P-256", 5) == 0)
    {
        group_name = "prime256v1";
    } else if (crv_str.len == 5
               && ngx_strncmp(crv_str.data, "P-384", 5) == 0)
    {
        group_name = "secp384r1";
    } else if (crv_str.len == 5
               && ngx_strncmp(crv_str.data, "P-521", 5) == 0)
    {
        group_name = "secp521r1";
    } else if (crv_str.len == 9
               && ngx_strncmp(crv_str.data, "secp256k1", 9) == 0)
    {
        group_name = "secp256k1";
    } else {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: unsupported curve: %V", &crv_str);
        return NULL;
    }

    /* Decode Base64url-encoded coordinates */
    x_decoded.len = ngx_base64_decoded_length(x_str.len);
    x_decoded.data = ngx_pnalloc(pool, x_decoded.len);
    if (x_decoded.data == NULL) {
        return NULL;
    }
    if (ngx_decode_base64url(&x_decoded, &x_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: failed to decode 'x' coordinate");
        return NULL;
    }

    y_decoded.len = ngx_base64_decoded_length(y_str.len);
    y_decoded.data = ngx_pnalloc(pool, y_decoded.len);
    if (y_decoded.data == NULL) {
        return NULL;
    }
    if (ngx_decode_base64url(&y_decoded, &y_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: failed to decode 'y' coordinate");
        return NULL;
    }

    /* Validate coordinate lengths for the curve */
    {
        size_t expected_coord_len;

        if (ngx_strncmp(crv_str.data, "P-256", 5) == 0
            || ngx_strncmp(crv_str.data, "secp256k1", 9) == 0)
        {
            expected_coord_len = 32;
        } else if (ngx_strncmp(crv_str.data, "P-384", 5) == 0) {
            expected_coord_len = 48;
        } else {
            /* P-521 */
            expected_coord_len = 66;
        }

        if (x_decoded.len != expected_coord_len) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "auth_gate_jwks: invalid 'x' coordinate length "
                          "for %V: %uz (expected %uz)",
                          &crv_str, x_decoded.len, expected_coord_len);
            return NULL;
        }

        if (y_decoded.len != expected_coord_len) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "auth_gate_jwks: invalid 'y' coordinate length "
                          "for %V: %uz (expected %uz)",
                          &crv_str, y_decoded.len, expected_coord_len);
            return NULL;
        }
    }

    /* Create uncompressed EC point format (0x04 || X || Y) */
    pub_key_len = 1 + x_decoded.len + y_decoded.len;
    pub_key = ngx_pnalloc(pool, pub_key_len);
    if (pub_key == NULL) {
        return NULL;
    }

    pub_key[0] = 0x04;
    ngx_memcpy(pub_key + 1, x_decoded.data, x_decoded.len);
    ngx_memcpy(pub_key + 1 + x_decoded.len, y_decoded.data, y_decoded.len);

    /* Build OpenSSL 3.0 parameters */
    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: OSSL_PARAM_BLD_new failed: %s",
                      err_buf);
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_utf8_string(param_bld,
                                         OSSL_PKEY_PARAM_GROUP_NAME,
                                         group_name, 0))
    {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: OSSL_PARAM_BLD push group failed: %s",
                      err_buf);
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_octet_string(param_bld,
                                          OSSL_PKEY_PARAM_PUB_KEY,
                                          pub_key, pub_key_len))
    {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: OSSL_PARAM_BLD push pubkey failed: %s",
                      err_buf);
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: OSSL_PARAM_BLD_to_param failed: %s",
                      err_buf);
        goto cleanup;
    }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (pctx == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: EVP_PKEY_CTX_new_from_name failed: %s",
                      err_buf);
        goto cleanup;
    }

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: EVP_PKEY_fromdata_init failed: %s",
                      err_buf);
        goto cleanup;
    }

    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: EVP_PKEY_fromdata failed: %s", err_buf);
        goto cleanup;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                   "auth_gate_jwks: EC public key created successfully");

cleanup:
    if (param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if (params != NULL) {
        OSSL_PARAM_free(params);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }

    return pkey;
}


static EVP_PKEY *
jwks_create_okp_key(nxe_json_t *jwk, ngx_pool_t *pool,
    ngx_log_t *log)
{
    ngx_str_t crv_str, x_str, x_decoded;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    const char *algorithm;
    size_t expected_len;
    char err_buf[256];

    ERR_clear_error();

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                   "auth_gate_jwks: creating EdDSA public key from JWK");

    if (jwks_get_string_field(jwk, "crv", &crv_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: missing or invalid 'crv' parameter");
        return NULL;
    }

    if (jwks_get_string_field(jwk, "x", &x_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: missing or invalid 'x' parameter");
        return NULL;
    }

    /* Determine curve and expected key length */
    if (crv_str.len == 7
        && ngx_strncmp(crv_str.data, "Ed25519", 7) == 0)
    {
        algorithm = "ED25519";
        expected_len = 32;
    } else if (crv_str.len == 5
               && ngx_strncmp(crv_str.data, "Ed448", 5) == 0)
    {
        algorithm = "ED448";
        expected_len = 57;
    } else {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: unsupported OKP curve: %V "
                      "(only Ed25519 and Ed448 supported)", &crv_str);
        return NULL;
    }

    /* Decode Base64url-encoded public key */
    x_decoded.len = ngx_base64_decoded_length(x_str.len);
    x_decoded.data = ngx_pnalloc(pool, x_decoded.len);
    if (x_decoded.data == NULL) {
        return NULL;
    }
    if (ngx_decode_base64url(&x_decoded, &x_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: failed to decode 'x' public key");
        return NULL;
    }

    if (x_decoded.len != expected_len) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: invalid %V public key length: %uz "
                      "(expected %uz)", &crv_str, x_decoded.len, expected_len);
        return NULL;
    }

    /* Build OpenSSL 3.0 parameters */
    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: OSSL_PARAM_BLD_new failed: %s",
                      err_buf);
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_octet_string(param_bld,
                                          OSSL_PKEY_PARAM_PUB_KEY,
                                          x_decoded.data, x_decoded.len))
    {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: OSSL_PARAM_BLD push pubkey failed: %s",
                      err_buf);
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: OSSL_PARAM_BLD_to_param failed: %s",
                      err_buf);
        goto cleanup;
    }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
    if (pctx == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: EVP_PKEY_CTX_new_from_name "
                      "failed for %s: %s", algorithm, err_buf);
        goto cleanup;
    }

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: EVP_PKEY_fromdata_init failed: %s",
                      err_buf);
        goto cleanup;
    }

    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: EVP_PKEY_fromdata failed: %s", err_buf);
        goto cleanup;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "auth_gate_jwks: %V public key created successfully",
                   &crv_str);

cleanup:
    if (param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if (params != NULL) {
        OSSL_PARAM_free(params);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }

    return pkey;
}


ngx_auth_gate_jwks_keyset_t *
ngx_auth_gate_jwks_parse(ngx_pool_t *pool, ngx_str_t *json, ngx_log_t *log)
{
    nxe_json_t *root, *keys_array, *jwk;
    ngx_auth_gate_jwks_keyset_t *keyset;
    ngx_auth_gate_jwks_key_t *key;
    ngx_str_t kty_str, kid_str, alg_str, crv_str, keys_field;
    EVP_PKEY *pkey;
    size_t i, array_size;
    ngx_pool_cleanup_t *cln;

    if (json == NULL || json->len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: empty JWKS JSON");
        return NULL;
    }

    if (json->len > NGX_AUTH_GATE_MAX_JWKS_SIZE) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: JWKS JSON too large: %uz", json->len);
        return NULL;
    }

    root = nxe_json_parse(json, pool);
    if (root == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: failed to parse JWKS JSON");
        return NULL;
    }

    /* Get "keys" array */
    ngx_str_set(&keys_field, "keys");
    keys_array = nxe_json_object_get_ns(root, &keys_field);
    if (keys_array == NULL || !nxe_json_is_array(keys_array)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_gate_jwks: missing or invalid 'keys' array");
        nxe_json_free(root);
        return NULL;
    }

    array_size = nxe_json_array_size(keys_array);

    if (array_size > NGX_AUTH_GATE_MAX_JWKS_KEYS) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "auth_gate_jwks: JWKS contains %uz keys, "
                      "limiting to %d", array_size,
                      NGX_AUTH_GATE_MAX_JWKS_KEYS);
        array_size = NGX_AUTH_GATE_MAX_JWKS_KEYS;
    }

    /* Allocate keyset */
    keyset = ngx_pcalloc(pool, sizeof(ngx_auth_gate_jwks_keyset_t));
    if (keyset == NULL) {
        nxe_json_free(root);
        return NULL;
    }

    keyset->keys = ngx_array_create(pool,
                                    array_size > 0 ? array_size : 1,
                                    sizeof(ngx_auth_gate_jwks_key_t));
    if (keyset->keys == NULL) {
        nxe_json_free(root);
        return NULL;
    }

    /* Register cleanup handler for EVP_PKEY resources */
    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        nxe_json_free(root);
        return NULL;
    }

    cln->handler = jwks_keyset_cleanup;
    cln->data = keyset;

    /* Iterate keys */
    for (i = 0; i < array_size; i++) {
        jwk = nxe_json_array_get(keys_array, i);
        if (jwk == NULL || !nxe_json_is_object(jwk)) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "auth_gate_jwks: invalid JWK at index %uz, "
                          "skipping", i);
            continue;
        }

        /* Skip encryption keys (use: "enc") */
        if (jwks_has_string_value(jwk, "use", "enc")) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                           "auth_gate_jwks: skipping encryption key "
                           "at index %uz", i);
            continue;
        }

        /* Get kty (key type) */
        if (jwks_get_string_field(jwk, "kty", &kty_str) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "auth_gate_jwks: missing 'kty' at index %uz, "
                          "skipping", i);
            continue;
        }

        /* Create EVP_PKEY based on key type */
        pkey = NULL;

        if (kty_str.len == 3
            && ngx_strncmp(kty_str.data, "RSA", 3) == 0)
        {
            pkey = jwks_create_rsa_key(jwk, pool, log);
        } else if (kty_str.len == 2
                   && ngx_strncmp(kty_str.data, "EC", 2) == 0)
        {
            pkey = jwks_create_ec_key(jwk, pool, log);
        } else if (kty_str.len == 3
                   && ngx_strncmp(kty_str.data, "OKP", 3) == 0)
        {
            pkey = jwks_create_okp_key(jwk, pool, log);
        } else {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "auth_gate_jwks: unsupported key type '%V' "
                          "at index %uz, skipping", &kty_str, i);
            continue;
        }

        if (pkey == NULL) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "auth_gate_jwks: failed to create key "
                          "at index %uz, skipping", i);
            continue;
        }

        /* Add key to array */
        key = ngx_array_push(keyset->keys);
        if (key == NULL) {
            EVP_PKEY_free(pkey);
            nxe_json_free(root);
            return NULL;
        }

        ngx_memzero(key, sizeof(ngx_auth_gate_jwks_key_t));

        /* Set key type */
        if (kty_str.len == 3
            && ngx_strncmp(kty_str.data, "RSA", 3) == 0)
        {
            key->kty = NGX_AUTH_GATE_JWK_RSA;
        } else if (kty_str.len == 2
                   && ngx_strncmp(kty_str.data, "EC", 2) == 0)
        {
            key->kty = NGX_AUTH_GATE_JWK_EC;
        } else {
            key->kty = NGX_AUTH_GATE_JWK_OKP;
        }

        /* Get kid (optional) */
        if (jwks_get_string_field(jwk, "kid", &kid_str) == NGX_OK) {
            key->kid.data = ngx_pstrdup(pool, &kid_str);
            if (key->kid.data == NULL) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "auth_gate_jwks: failed to copy kid "
                              "at index %uz, skipping", i);
                EVP_PKEY_free(pkey);
                keyset->keys->nelts--;
                continue;
            }
            key->kid.len = kid_str.len;
        }

        /* Get alg (optional) */
        if (jwks_get_string_field(jwk, "alg", &alg_str) == NGX_OK) {
            key->alg.data = ngx_pstrdup(pool, &alg_str);
            if (key->alg.data == NULL) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "auth_gate_jwks: failed to copy alg "
                              "at index %uz, skipping", i);
                EVP_PKEY_free(pkey);
                keyset->keys->nelts--;
                continue;
            }
            key->alg.len = alg_str.len;
        }

        /* Get crv for EC keys (used for alg-curve validation) */
        if (key->kty == NGX_AUTH_GATE_JWK_EC
            && jwks_get_string_field(jwk, "crv", &crv_str) == NGX_OK)
        {
            key->crv.data = ngx_pstrdup(pool, &crv_str);
            if (key->crv.data == NULL) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "auth_gate_jwks: failed to copy crv "
                              "at index %uz, skipping", i);
                EVP_PKEY_free(pkey);
                keyset->keys->nelts--;
                continue;
            }
            key->crv.len = crv_str.len;
        }

        key->pkey = pkey;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "auth_gate_jwks: added key kid='%V', alg='%V'",
                       &key->kid, &key->alg);
    }

    nxe_json_free(root);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "auth_gate_jwks: successfully parsed %uz keys",
                   keyset->keys->nelts);

    return keyset;
}
