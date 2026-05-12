use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== eq: simple claim match
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

=== eq: simple claim mismatch
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .role eq "guest";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !eq: negated equal (different value passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .role !eq "guest";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !eq: negated equal (same value fails)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .role !eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== eq: empty string check
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_guest .sub eq "";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !eq: empty string negation (non-empty passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .sub !eq "";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== eq: integer with json= prefix
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .age eq json=25;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== eq: integer mismatch with json= prefix
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .age eq json=30;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== gt: numeric greater than
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .age gt json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== gt: numeric not greater than
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_guest .age gt json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== ge: numeric greater or equal (greater)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .age ge json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== ge: numeric greater or equal (equal)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .age ge json=25;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== lt: numeric less than
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_guest .age lt json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== lt: numeric not less than
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .age lt json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== le: numeric less or equal (less)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_guest .age le json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== le: numeric less or equal (equal)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_guest .age le json=15;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== in: value in json= array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .role in json=["staff","admin","viewer"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== in: value not in json= array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_guest .role in json=["staff","admin"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !in: negated in (not contained passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_guest .role !in json=["staff","admin"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !in: negated in (contained fails)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .role !in json=["staff","admin"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== any: arrays share common element
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .groups any json=["staff","viewer"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== any: arrays have no common element
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .groups any json=["viewer","manager"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !any: negated any (no common element passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .groups !any json=["viewer","manager"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !any: negated any (common element fails)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .groups !any json=["staff","viewer"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== match: regex on string claim
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .email match "@example\.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== match: regex no match
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_guest .email match "@example\.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !match: negated regex (no match passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_guest .email !match "@example\.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== nested claim: dot notation
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .nested.key eq "value";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== nested claim: mismatch
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .nested.key eq "wrong";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== array index: first element
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .keys[0] eq "primary";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== array index: second element
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .keys[1] eq "secondary";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== deep nested claim: resource_access
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_api .resource_access.my-app.roles any json=["admin"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== deep nested claim: resource_access mismatch
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_api .resource_access.my-app.roles any json=["viewer"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== scope: array in check
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_api .scope any json=["api:read"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== issuer: string match
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_api .iss eq "https://accounts.example.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== issuer: string mismatch
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_api .iss eq "https://evil.example.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== audience: string match
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_api .aud eq "my-app";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== claim not found
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .nonexistent eq "value";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== invalid JWT variable
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $bad_jwt "not-a-jwt";
  auth_gate_jwt $bad_jwt .field eq "value";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== custom error code: error=401
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_guest .role eq "admin" error=401;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401

=== multiple directives: AND logic, both pass
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .role eq "admin";
  auth_gate_jwt $jwt_admin .age ge json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== multiple directives: AND logic, second fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .role eq "admin";
  auth_gate_jwt $jwt_admin .age lt json=18 error=403;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== eq: array comparison with json= prefix
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .groups eq json=["admin","staff"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== issuer: regex match
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_api .iss match "^https://accounts\.example\.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== grouping: same variable 3 rules, all pass
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .role eq "admin";
  auth_gate_jwt $jwt_admin .age ge json=18;
  auth_gate_jwt $jwt_admin .sub eq "user1";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== grouping: same variable 3 rules, middle fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .role eq "admin";
  auth_gate_jwt $jwt_admin .age lt json=18;
  auth_gate_jwt $jwt_admin .sub eq "user1";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== grouping: same variable, custom error in group
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .role eq "admin";
  auth_gate_jwt $jwt_admin .age gt json=30 error=401;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401

=== grouping: two variables, all pass
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .role eq "admin";
  auth_gate_jwt $jwt_guest .role eq "guest";
  auth_gate_jwt $jwt_admin .age ge json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== grouping: two variables, second group fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_admin .role eq "admin";
  auth_gate_jwt $jwt_guest .role eq "admin";
  auth_gate_jwt $jwt_admin .age ge json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== grouping: inherited from server, all pass
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
auth_gate_jwt $jwt_admin .role eq "admin";
location / {
  auth_gate_jwt $jwt_admin .age ge json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== grouping: inherited from server, child fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
auth_gate_jwt $jwt_admin .role eq "admin";
location / {
  auth_gate_jwt $jwt_admin .age gt json=30;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== malformed JWT: no dot separator returns 403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $jwt "notavalidjwt";
  auth_gate_jwt $jwt .role eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== malformed JWT: single dot returns 403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $jwt "header.";
  auth_gate_jwt $jwt .role eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== malformed JWT: empty payload returns 403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $jwt "eyJhbGciOiJub25lIn0..";
  auth_gate_jwt $jwt .role eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== malformed JWT: invalid base64 payload returns 403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $jwt "eyJhbGciOiJub25lIn0.!!!invalid!!!.";
  auth_gate_jwt $jwt .role eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== JWT token too large
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
large_client_header_buffers 4 32k;
--- config
location / {
  auth_gate_jwt $http_x_jwt .sub eq "test";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers eval
my $big = "A" x 17000;
"X-JWT: eyJhbGciOiJub25lIn0.${big}."
--- request
GET /
--- error_code: 403
--- error_log
nxe_jwx: token exceeds

=== JWT scalar payload with non-root field path must deny
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  # payload: 42 (scalar integer)
  set $jwt "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.NDI.";
  auth_gate_jwt $jwt .sub eq "test";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== JWT bracket key (URL claim)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  # payload: {"sub":"user1","https://example.com/role":"editor"}
  set $jwt "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMSIsImh0dHBzOi8vZXhhbXBsZS5jb20vcm9sZSI6ImVkaXRvciJ9.";
  auth_gate_jwt $jwt '.["https://example.com/role"]' eq "editor";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200
