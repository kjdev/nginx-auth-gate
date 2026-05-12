use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== !gt with type mismatch (string vs number) must deny
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .role !gt json=42;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !lt with type mismatch (string vs number) must deny
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .role !lt json=42;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !ge with type mismatch (string vs number) must deny
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .role !ge json=42;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !le with type mismatch (string vs number) must deny
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .role !le json=42;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !any with non-array actual must deny
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .role !any json=["x","y"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !gt normal negation (25 !gt 3 => deny)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age !gt json=3;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !gt normal negation (25 !gt 30 => allow)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age !gt json=30;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !ge normal negation (25 !ge 25 => deny)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age !ge json=25;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !ge normal negation (25 !ge 30 => allow)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age !ge json=30;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !lt normal negation (25 !lt 30 => deny)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age !lt json=30;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !lt normal negation (25 !lt 3 => allow)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age !lt json=3;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !le normal negation (25 !le 25 => deny)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age !le json=25;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !le normal negation (25 !le 3 => allow)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age !le json=3;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== in operator with object (key found)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
set $obj_roles '{"admin":1,"editor":1}';
location / {
  auth_gate_json $json_admin .role in json=$obj_roles;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== in operator with object (key not found)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
set $obj_roles '{"editor":1,"viewer":1}';
location / {
  auth_gate_json $json_admin .role in json=$obj_roles;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !in operator with object (key found => deny)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
set $obj_roles '{"admin":1,"editor":1}';
location / {
  auth_gate_json $json_admin .role !in json=$obj_roles;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !in operator with object (key not found => allow)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
set $obj_roles '{"editor":1,"viewer":1}';
location / {
  auth_gate_json $json_admin .role !in json=$obj_roles;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== in operator with object (non-string actual => deny)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
set $obj_nums '{"25":1,"30":1}';
location / {
  auth_gate_json $json_admin .age in json=$obj_nums;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== error=444 must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "ok";
  auth_gate $var error=444;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== JSON_REJECT_DUPLICATES: duplicate keys must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"role":"admin","role":"guest"}';
  auth_gate_json $json .role eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== PCRE match_limit: catastrophic backtracking must be caught
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  auth_gate $var match "(.*a){20}";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403
--- error_log
auth_gate: regex match limit exceeded

=== !match with dynamic pattern must be rate-limited
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "test";
  set $pat "^test";
  auth_gate $var !match $pat;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== invalid constant json= value must be rejected at configure time
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var '{"role":"admin"}';
  auth_gate_json $var .role eq json=invalid;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== invalid constant json= value in auth_gate must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "hello";
  auth_gate $var eq json={broken;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== valid constant json= value must be accepted
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .role eq json="admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== Field depth: 33 segments must be rejected (max 32)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{}';
  auth_gate_json $json .a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.aa.ab.ac.ad.ae.af.ag eq "x";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== !in with scalar expected (NGX_ERROR must pass through negation)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .role !in json=42;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !match with non-string field (NGX_ERROR must pass through negation)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age !match "\\d+";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== in operator: array size exceeds limit (1024)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .role in json=$http_x_expected;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers eval
my $array = "[" . CORE::join(",", 1..1025) . "]";
"X-Expected: $array"
--- request
GET /
--- error_code: 403
--- error_log
auth_gate: in operator array size exceeds limit

=== any operator: individual array size exceeds limit (1024)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_gate_json $http_x_actual . any json=[1];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers eval
my $array = "[" . CORE::join(",", 1..1025) . "]";
"X-Actual: $array"
--- request
GET /
--- error_code: 403
--- error_log
auth_gate: any operator array size exceeds limit

=== Field index exceeds limit (65535)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '[]';
  auth_gate_json $json .[65536] eq "x";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== Dynamic regex pattern size exceeds limit (8192)
--- http_config
large_client_header_buffers 4 16384;
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var 'test';
  auth_gate $var match $http_x_pattern;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers eval
my $pat = "^" . ("a" x 8192);
"X-Pattern: $pat"
--- request
GET /
--- error_code: 403
--- error_log
auth_gate: match operator pattern size exceeds limit

=== match with non-string JSON field (without negation)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age match "\\d+";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== mixed directives: auth_gate + auth_gate_json AND logic
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  set $enabled "1";
  auth_gate $enabled;
  auth_gate_json $json_admin .role eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== mixed directives: auth_gate fails, auth_gate_json not reached
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  set $enabled "";
  auth_gate $enabled error=401;
  auth_gate_json $json_admin .role eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401

=== scalar JSON with field path uses correct error code (2nd req)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_scalar . eq "x" error=401;
  auth_gate_json $json_scalar .field eq "x" error=403;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== scalar JWT payload is rejected by decode (RFC 7519: payload must be object)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_scalar . eq "x" error=401;
  auth_gate_jwt $jwt_scalar .field eq "x" error=403;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401
--- error_log
nxe_jwx: payload is not a JSON object

=== field index with leading zeros must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '[]';
  auth_gate_json $json .[007] eq "x";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== Dynamic regex compile count limit (17 > 16)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "test";
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  auth_gate $var match $http_x_pat;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers
X-Pat: ^test$
--- request
GET /
--- error_code: 403
--- error_log
auth_gate: dynamic regex compilation limit exceeded

=== config error: auth_gate_jwt without dot prefix
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $jwt "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.";
  auth_gate_jwt $jwt sub eq "test";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== Field index boundary: 65535 must be accepted
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '[1]';
  auth_gate_json $json .[65535] eq "x";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== config error: error=abc must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "ok";
  auth_gate $var error=abc;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== config error: non-field-path argument (missing dot prefix)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"role":"admin"}';
  auth_gate_json $json role eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== dynamic match: invalid regex must return 403 (not bypass)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "test";
  auth_gate $var match $http_x_pat;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers
X-Pat: [invalid
--- request
GET /
--- error_code: 403
--- error_log
auth_gate: dynamic regex compile failed

=== dynamic !match: invalid regex must return 403 (NGX_ERROR transparent)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "test";
  auth_gate $var !match $http_x_pat;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers
X-Pat: [invalid
--- request
GET /
--- error_code: 403
--- error_log
auth_gate: dynamic regex compile failed

=== dynamic json= invalid JSON must return 403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"role":"admin"}';
  auth_gate_json $json .role eq json=$http_x_expected;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers
X-Expected: {invalid json
--- request
GET /
--- error_code: 403
--- error_log
auth_gate: expected value parse failed

=== auth_gate_json: match_limit exceeded must return 403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"val":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}';
  auth_gate_json $json .val match "(.*a){20}";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403
--- error_log
auth_gate: regex match limit exceeded

=== Field depth: exactly 32 segments must be accepted
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_gate_json $http_x_json .a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.aa.ab.ac.ad.ae.af eq "x";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers eval
use JSON::PP;
my $data = {};
my $cur = $data;
my @keys = ('a'..'z', 'aa'..'af');
for my $i (0..$#keys-1) {
    $cur->{$keys[$i]} = {};
    $cur = $cur->{$keys[$i]};
}
$cur->{$keys[-1]} = "x";
"X-Json: " . JSON::PP->new->encode($data)
--- request
GET /
--- error_code: 200

=== in operator: array size exactly 1024 must be accepted
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .role in json=$http_x_expected;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers eval
my $array = '["admin",' . CORE::join(",", 2..1024) . "]";
"X-Expected: $array"
--- request
GET /
--- error_code: 200

=== !eq json=null: non-existent field must deny (field not found)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .nonexistent !eq json=null;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403
--- error_log
auth_gate: field not found

=== config error: consecutive dots in field path must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"a":{"b":1}}';
  auth_gate_json $json .a..b eq json=1;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== config error: leading consecutive dots in field path must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"role":"admin"}';
  auth_gate_json $json ..role eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== config error: auth_gate with only error= (no variables) must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_gate error=401;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== expected value exceeding size limit (65536) must be rejected
--- http_config
large_client_header_buffers 4 131072;
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"role":"admin"}';
  auth_gate_json $json .role eq $http_x_expected;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers eval
my $val = "a" x 65537;
"X-Expected: $val"
--- request
GET /
--- error_code: 403
--- error_log
auth_gate: expected value too large

=== string fallback: "9" ge "18" is true (string comparison, not numeric)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "9";
  auth_gate $var ge "18";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== dynamic pattern with JSON NUL escape must be rejected
Jansson 2.14 rejects \u0000 without JSON_ALLOW_NUL, so the expected
value parse fails before reaching the match operator NUL check.
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"name":"test"}';
  auth_gate_json $json .name match json=$http_x_pat;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers
X-Pat: "admin\u0000x"
--- request
GET /
--- error_code: 403
--- error_log
auth_gate: expected value parse failed

=== JSON with NUL escape in subject must be rejected at parse
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_gate_json $http_x_json .name match "^admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers
X-Json: {"name":"admin\u0000guest"}
--- request
GET /
--- error_code: 403
--- error_log
auth_gate_json: JSON parse failed

=== eq with NUL escape in JSON subject must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_gate_json $http_x_json .name eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers
X-Json: {"name":"admin\u0000bypass"}
--- request
GET /
--- error_code: 403
--- error_log
auth_gate_json: JSON parse failed

=== any operator comparison count at exact limit (100x100=10000)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_gate_json $http_x_actual . any json=$http_x_expected;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- more_headers eval
my $actual = "[" . CORE::join(",", 1..100) . "]";
my $expected = "[" . CORE::join(",", 1..100) . "]";
"X-Actual: $actual\nX-Expected: $expected"
--- request
GET /
--- error_code: 200

=== eq with integer field vs string expected (type mismatch)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age eq "25";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !eq with integer field vs string expected (type mismatch => NGX_DECLINED => negation allows)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age !eq "25";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== JWT array payload is rejected by decode (RFC 7519: payload must be object)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $jwt "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.WzEsMiwzXQ.";
  auth_gate_jwt $jwt .[0] eq json=1;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403
--- error_log
nxe_jwx: payload is not a JSON object

=== JWT array payload - key access must fail
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $jwt "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.WzEsMiwzXQ.";
  auth_gate_jwt $jwt .key eq "x";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== empty JSON variable must return 403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '';
  auth_gate_json $json .key eq "x";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== empty JWT variable must return 403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $jwt '';
  auth_gate_jwt $jwt .key eq "x";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== trailing dot in field path must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"key":"val"}';
  auth_gate_json $json .key. eq "val";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== array index out of range must return 403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '["a","b"]';
  auth_gate_json $json .[100] eq "x";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== eq with nested objects (deep equality success)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
set $expected '{"key":"value"}';
location / {
  auth_gate_json $json_admin .nested eq json=$expected;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== eq with nested objects (deep equality failure)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
set $expected '{"key":"wrong"}';
location / {
  auth_gate_json $json_admin .nested eq json=$expected;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== auth_gate pass + auth_gate_jwt fail => 403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  set $enabled "1";
  auth_gate $enabled;
  auth_gate_jwt $jwt_admin .role eq "guest";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== JWE-like 5-segment token must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $jwt "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0Iiwicm9sZSI6ImFkbWluIn0.sig.extra1.extra2";
  auth_gate_jwt $jwt .role eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== in operator with numeric array elements (match)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age in json=[25,30];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== in operator with string array vs integer field (type mismatch)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .age in json=["25","30"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== boolean mode multiple error= (last wins)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "";
  auth_gate $var error=401 error=403;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== negated operator log should not double ! prefix
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .role !eq "guest";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== negated operator failure log uses operator_name directly
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .role !eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403
--- error_log
auth_gate: !eq check failed
--- no_error_log
!!eq

=== in operator with mixed-type array (string match)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_json $json_admin .role in json=["admin",42,true,null];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== field path: trailing chars after bracket must be rejected (.a[0]b)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"a":["x"]}';
  auth_gate_json $json .a[0]b eq "x";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== field path: trailing chars after dot-bracket must be rejected (.[0]b)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '["x"]';
  auth_gate_json $json .[0]b eq "x";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== config error: empty json= payload must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"role":"admin"}';
  auth_gate_json $json .role eq json=;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== precompiled match with json= prefix must extract string pattern
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"role":"admin"}';
  auth_gate_json $json .role match json="^admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== precompiled match with json= non-string must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"role":"admin"}';
  auth_gate_json $json .role match json=42;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== JWT with empty header segment must be rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $jwt ".eyJzdWIiOiJ0ZXN0In0.sig";
  auth_gate_jwt $jwt .sub eq "test";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403
