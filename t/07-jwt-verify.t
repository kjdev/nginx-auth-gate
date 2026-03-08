use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== RS256: signature verification success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200
--- no_error_log
[error]

=== ES256: signature verification success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_es256 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200
--- no_error_log
[error]

=== EdDSA: signature verification success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_eddsa jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200
--- no_error_log
[error]

=== verify + claim check: both pass
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_uri;
    auth_gate_jwt $jwt_rs256 .sub eq "user1" error=403;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200
--- no_error_log
[error]

=== verify + claim check: verify passes, claim fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_uri;
    auth_gate_jwt $jwt_rs256 .sub eq "wrong_user" error=403;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== bad signature: verification fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_bad_sig jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jws: signature verification failed

=== alg:none JWT: rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_none jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jws: algorithm 'none' is not allowed

=== JWKS fetch failure (500): returns error
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_fail {
    internal;
    return 500 '{"error":"internal"}';
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_fail;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jwt_verify: JWKS fetch returned status

=== invalid JWKS JSON: returns error
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_bad {
    internal;
    return 200 'not-json';
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_bad;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jwt_verify: JWKS parse failed

=== custom error code
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_bad_sig jwks=/jwks_uri error=403;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== empty token: returns error
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
set $jwt_empty "";
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_empty jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jwt_verify: empty token

=== backward compat: auth_gate_jwt without verify still works
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
    auth_gate_jwt $jwt_admin .role eq "admin";
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== kid mismatch: verification fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_wrong_kid {
    internal;
    return 200 '{"keys":[{"kty":"RSA","kid":"wrong-kid","alg":"RS256","use":"sig","n":"jQWGnhjORAr-gmZUxoAEi7TzNszRVPkssSkeIkhyU1lOT_9swNNqTYM13BGQxaVOho-uB3aaCaQNEcAZ5OihjX0MwJtx-UWzZlkN9R1SwdX0-ZWBuJbkKF9ZzsnW0fshh6RI_S-sre6TBISpi9O3Ak7omES3RFivVMK4-pNVYX6bPuD2MJ5lhEfxAwhaGXH5kyOj0iaBJisTrqMi_AuL4GX8w4ZkLhlCVdN2W3cjysQacSi-iJiO8mXX-9wfYiXzseTsLe4r60Af4YTr12mm-b6twCNCkmq-wfgqHIGH1kneni-Xc18pVcdyZgE94sTa198X5y5VQyrjsRJp4dgPJQ","e":"AQAB"}]}';
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_wrong_kid;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jws: signature verification failed

=== multiple verify: different URIs, both pass
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_rsa {
    internal;
    return 200 '{"keys":[{"kty":"RSA","kid":"rsa-test-key","alg":"RS256","use":"sig","n":"jQWGnhjORAr-gmZUxoAEi7TzNszRVPkssSkeIkhyU1lOT_9swNNqTYM13BGQxaVOho-uB3aaCaQNEcAZ5OihjX0MwJtx-UWzZlkN9R1SwdX0-ZWBuJbkKF9ZzsnW0fshh6RI_S-sre6TBISpi9O3Ak7omES3RFivVMK4-pNVYX6bPuD2MJ5lhEfxAwhaGXH5kyOj0iaBJisTrqMi_AuL4GX8w4ZkLhlCVdN2W3cjysQacSi-iJiO8mXX-9wfYiXzseTsLe4r60Af4YTr12mm-b6twCNCkmq-wfgqHIGH1kneni-Xc18pVcdyZgE94sTa198X5y5VQyrjsRJp4dgPJQ","e":"AQAB"}]}';
}
location = /jwks_ec {
    internal;
    return 200 '{"keys":[{"kty":"EC","kid":"ec-test-key","alg":"ES256","use":"sig","crv":"P-256","x":"vJzNxVmk9yPWg7wFj6_pO8PBQH9yfyZP23t9onJoI84","y":"kLq1Cb3LPBEBfPjopCBophW64Y4lhRfa-sYqtNXPNO0"}]}';
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_rsa;
    auth_gate_jwt_verify $jwt_es256 jwks=/jwks_ec;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200
--- no_error_log
[error]

=== multiple verify: same URI, both pass (subrequest dedup)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_uri;
    auth_gate_jwt_verify $jwt_es256 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200
--- no_error_log
[error]

=== multiple verify: first fails, returns its error code
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_bad_sig jwks=/jwks_uri error=403;
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== multiple verify: second fails, returns its error code
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_uri;
    auth_gate_jwt_verify $jwt_bad_sig jwks=/jwks_uri error=403;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== ES256K: signature verification success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_es256k jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== PS256: signature verification success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_ps256 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== RS384: signature verification success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_rs384 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== PS384: signature verification success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_ps384 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== PS512: signature verification success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_ps512 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== RS512: signature verification success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_rs512 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== empty JWKS keys array: verification fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_empty {
    internal;
    return 200 '{"keys":[]}';
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_empty;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jws: invalid arguments for verification

=== JWKS with only encryption keys: verification fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_enc {
    internal;
    return 200 '{"keys":[{"kty":"RSA","kid":"rsa-test-key","alg":"RS256","use":"enc","n":"jQWGnhjORAr-gmZUxoAEi7TzNszRVPkssSkeIkhyU1lOT_9swNNqTYM13BGQxaVOho-uB3aaCaQNEcAZ5OihjX0MwJtx-UWzZlkN9R1SwdX0-ZWBuJbkKF9ZzsnW0fshh6RI_S-sre6TBISpi9O3Ak7omES3RFivVMK4-pNVYX6bPuD2MJ5lhEfxAwhaGXH5kyOj0iaBJisTrqMi_AuL4GX8w4ZkLhlCVdN2W3cjysQacSi-iJiO8mXX-9wfYiXzseTsLe4r60Af4YTr12mm-b6twCNCkmq-wfgqHIGH1kneni-Xc18pVcdyZgE94sTa198X5y5VQyrjsRJp4dgPJQ","e":"AQAB"}]}';
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_enc;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jws: invalid arguments for verification

=== config error: missing variable prefix $
--- config
location / {
    auth_gate_jwt_verify token jwks=/jwks_uri;
}
--- must_die

=== config error: missing jwks= prefix
--- config
location / {
    auth_gate_jwt_verify $token /jwks_uri;
}
--- must_die

=== config error: jwks URI not starting with /
--- config
location / {
    auth_gate_jwt_verify $token jwks=http://example.com/jwks;
}
--- must_die

=== config error: duplicate variable
--- config
location / {
    auth_gate_jwt_verify $token jwks=/jwks_uri;
    auth_gate_jwt_verify $token jwks=/jwks_uri2;
}
--- must_die

=== ES384: signature verification success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_es384 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== ES512: signature verification success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_es512 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== Ed448: signature verification success
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_ed448 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== HS256: HMAC algorithm rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_hs256 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jws: HMAC algorithm

=== merge: child overrides parent (child valid JWKS)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_bad;
location = /jwks_bad {
    internal;
    return 200 'not-json';
}
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== merge: child overrides parent (child invalid JWKS)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_uri;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location = /jwks_bad {
    internal;
    return 200 'not-json';
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_bad;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jwt_verify: JWKS parse failed

=== default error code is 401
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_bad_sig jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401

=== duplicate error= (last wins)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_bad_sig jwks=/jwks_uri error=401 error=403;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== merge: child inherits parent when no override
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_uri;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== JWE token (5 segments): rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_jwe jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jws: JWT has more than 3 segments

=== JWKS key without alg field: matches by kty (RS256)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_no_alg {
    internal;
    return 200 '{"keys":[{"kty":"RSA","kid":"rsa-test-key","use":"sig","n":"jQWGnhjORAr-gmZUxoAEi7TzNszRVPkssSkeIkhyU1lOT_9swNNqTYM13BGQxaVOho-uB3aaCaQNEcAZ5OihjX0MwJtx-UWzZlkN9R1SwdX0-ZWBuJbkKF9ZzsnW0fshh6RI_S-sre6TBISpi9O3Ak7omES3RFivVMK4-pNVYX6bPuD2MJ5lhEfxAwhaGXH5kyOj0iaBJisTrqMi_AuL4GX8w4ZkLhlCVdN2W3cjysQacSi-iJiO8mXX-9wfYiXzseTsLe4r60Af4YTr12mm-b6twCNCkmq-wfgqHIGH1kneni-Xc18pVcdyZgE94sTa198X5y5VQyrjsRJp4dgPJQ","e":"AQAB"}]}';
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_no_alg;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== JWKS key without alg field: matches by kty (ES256)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_no_alg_ec {
    internal;
    return 200 '{"keys":[{"kty":"EC","kid":"ec-test-key","use":"sig","crv":"P-256","x":"vJzNxVmk9yPWg7wFj6_pO8PBQH9yfyZP23t9onJoI84","y":"kLq1Cb3LPBEBfPjopCBophW64Y4lhRfa-sYqtNXPNO0"}]}';
}
location / {
    auth_gate_jwt_verify $jwt_es256 jwks=/jwks_no_alg_ec;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== JWKS key without alg field: matches by kty (EdDSA)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_no_alg_okp {
    internal;
    return 200 '{"keys":[{"kty":"OKP","kid":"ed-test-key","use":"sig","crv":"Ed25519","x":"0uIZsoGlxbGntqCAEYXHH7QjA9ffMu-8KL7erjWZNoc"}]}';
}
location / {
    auth_gate_jwt_verify $jwt_eddsa jwks=/jwks_no_alg_okp;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== alg confusion: RS256 token against EC-only JWKS rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_ec_only {
    internal;
    return 200 '{"keys":[{"kty":"EC","kid":"ec-test-key","alg":"ES256","use":"sig","crv":"P-256","x":"vJzNxVmk9yPWg7wFj6_pO8PBQH9yfyZP23t9onJoI84","y":"kLq1Cb3LPBEBfPjopCBophW64Y4lhRfa-sYqtNXPNO0"}]}';
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_ec_only;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jws: signature verification failed

=== alg confusion: ES256 token against RSA-only JWKS rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_rsa_only {
    internal;
    return 200 '{"keys":[{"kty":"RSA","kid":"rsa-test-key","alg":"RS256","use":"sig","n":"jQWGnhjORAr-gmZUxoAEi7TzNszRVPkssSkeIkhyU1lOT_9swNNqTYM13BGQxaVOho-uB3aaCaQNEcAZ5OihjX0MwJtx-UWzZlkN9R1SwdX0-ZWBuJbkKF9ZzsnW0fshh6RI_S-sre6TBISpi9O3Ak7omES3RFivVMK4-pNVYX6bPuD2MJ5lhEfxAwhaGXH5kyOj0iaBJisTrqMi_AuL4GX8w4ZkLhlCVdN2W3cjysQacSi-iJiO8mXX-9wfYiXzseTsLe4r60Af4YTr12mm-b6twCNCkmq-wfgqHIGH1kneni-Xc18pVcdyZgE94sTa198X5y5VQyrjsRJp4dgPJQ","e":"AQAB"}]}';
}
location / {
    auth_gate_jwt_verify $jwt_es256 jwks=/jwks_rsa_only;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jws: signature verification failed

=== non-whitelist algorithm (RS128): rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_rs128 jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
is not in whitelist

=== JWKS alg mismatch: JWKS has RS384 but JWT has RS256
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_alg_mismatch {
    internal;
    return 200 '{"keys":[{"kty":"RSA","kid":"rsa-test-key","alg":"RS384","use":"sig","n":"jQWGnhjORAr-gmZUxoAEi7TzNszRVPkssSkeIkhyU1lOT_9swNNqTYM13BGQxaVOho-uB3aaCaQNEcAZ5OihjX0MwJtx-UWzZlkN9R1SwdX0-ZWBuJbkKF9ZzsnW0fshh6RI_S-sre6TBISpi9O3Ak7omES3RFivVMK4-pNVYX6bPuD2MJ5lhEfxAwhaGXH5kyOj0iaBJisTrqMi_AuL4GX8w4ZkLhlCVdN2W3cjysQacSi-iJiO8mXX-9wfYiXzseTsLe4r60Af4YTr12mm-b6twCNCkmq-wfgqHIGH1kneni-Xc18pVcdyZgE94sTa198X5y5VQyrjsRJp4dgPJQ","e":"AQAB"}]}';
}
location / {
    auth_gate_jwt_verify $jwt_rs256 jwks=/jwks_alg_mismatch;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jws: signature verification failed

=== JWT without kid: matches JWKS key by kty (valid signature)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_no_kid_key {
    internal;
    return 200 '{"keys":[{"kty":"RSA","kid":"test-key-no-kid-jwt","use":"sig","n":"tGa1_qaiSJbvQzlnbHpGGnPsuesOM2li08i4wH9Vca-ek2mZU5nXvvFDZG2Unen_uVSa75PaY3mUEHSuwy_7g-NED2XtZ0AVezd6XyrG_qA6wLBzD0dnqC1JY62t9j-NB8Gw_Hq4QQAnYVsWm_Vt-7-VVZE6koKa8CgrDR5JUPXXbzGxcJEDkZA2pa92lzCfOlx2Hh5J84WWXFlY0McFMKhjWAVclDfAosHqDFBRq8I9yVxqQ_ck0vxYsRWiwBz9uLhBmkgPutTdV5ds_PiqKeiPr59ukCzaScTyS1z55NBGFmmSP5UhSjhcgn2mcwX4sS4gzg9V2Z-WxvCfGv8Kvw","e":"AQAB"}]}';
}
location / {
    auth_gate_jwt_verify $jwt_rs256_no_kid jwks=/jwks_no_kid_key;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== JWT without kid: fails with wrong key
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_rs256_no_kid jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jws: signature verification failed

=== JWT header without alg field: rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_no_alg jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jws: missing 'alg' in JWT header

=== invalid base64url signature: rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
include $TEST_NGINX_CONF_DIR/jwt_verify_vars.conf;
location = /jwks_uri {
    internal;
    include $TEST_NGINX_CONF_DIR/jwks_return.conf;
}
location / {
    auth_gate_jwt_verify $jwt_bad_b64sig jwks=/jwks_uri;
    include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
auth_gate_jws: failed to decode JWT signature
