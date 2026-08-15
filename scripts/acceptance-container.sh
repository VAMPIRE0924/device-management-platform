#!/bin/sh
set -eu

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
run_id="$(date +%s)-$$"
image="device-management-platform/local:container-acceptance"
primary="device-management-platform-acceptance-$run_id"
restored="platform-restored-$run_id"
primary_volume="device-management-platform-acceptance-data-$run_id"
restored_volume="platform-restored-data-$run_id"
certificate_volume="platform-certificate-data-$run_id"
primary_port="${DMP_CONTAINER_ACCEPTANCE_PORT:-18090}"
https_port="${DMP_CONTAINER_HTTPS_PORT:-18490}"
restored_port="${DMP_CONTAINER_RESTORE_PORT:-18091}"
access_http_port="${DMP_CONTAINER_ACCESS_HTTP_PORT:-18092}"
access_https_port="${DMP_CONTAINER_ACCESS_HTTPS_PORT:-18492}"
artifact_dir=$(mktemp -d /tmp/device-management-platform-container-acceptance.XXXXXX)

cleanup() {
  docker rm -f "$primary" "$restored" >/dev/null 2>&1 || true
  docker volume rm "$primary_volume" "$restored_volume" "$certificate_volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

command -v docker >/dev/null
command -v curl >/dev/null
command -v sqlite3 >/dev/null
command -v openssl >/dev/null
docker info >/dev/null

docker build --build-arg VERSION=container-acceptance -t "$image" "$project_dir"
if docker scout version >/dev/null 2>&1; then
  docker scout cves "$image" --only-severity critical,high --exit-code
else
  printf 'Docker Scout unavailable; image CVE scan skipped\n' >&2
fi
docker volume create "$primary_volume" >/dev/null
docker volume create "$certificate_volume" >/dev/null
mkdir -p "$artifact_dir/certificate-source/panel" "$artifact_dir/certificate-source/access"
cat >"$artifact_dir/panel-openssl.cnf" <<'EOF'
[req]
distinguished_name=dn
x509_extensions=san
prompt=no
[dn]
CN=panel.container.example.test
[san]
subjectAltName=DNS:panel.container.example.test
EOF
cat >"$artifact_dir/access-openssl.cnf" <<'EOF'
[req]
distinguished_name=dn
x509_extensions=san
prompt=no
[dn]
CN=*.container-remote.example.test
[san]
subjectAltName=DNS:*.container-remote.example.test
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -config "$artifact_dir/panel-openssl.cnf" \
  -keyout "$artifact_dir/certificate-source/panel/privkey.pem" -out "$artifact_dir/certificate-source/panel/fullchain.pem" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -config "$artifact_dir/access-openssl.cnf" \
  -keyout "$artifact_dir/certificate-source/access/privkey.pem" -out "$artifact_dir/certificate-source/access/fullchain.pem" >/dev/null 2>&1
docker run --rm --entrypoint sh -v "$certificate_volume:/cert" -v "$artifact_dir/certificate-source:/source:ro" "$image" -c \
  'mkdir -p /cert/panel /cert/access && cp /source/panel/*.pem /cert/panel/ && cp /source/access/*.pem /cert/access/ && chown -R root:root /cert && chmod 0700 /cert /cert/panel /cert/access && chmod 0600 /cert/panel/*.pem /cert/access/*.pem'
certificate_digest=$(docker run --rm --entrypoint sh -v "$certificate_volume:/cert:ro" "$image" -c \
  'sha256sum /cert/panel/fullchain.pem /cert/panel/privkey.pem /cert/access/fullchain.pem /cert/access/privkey.pem')
docker run -d --name "$primary" --restart no --security-opt no-new-privileges:true \
  -p "127.0.0.1:$primary_port:80" -v "$primary_volume:/data" "$image" >/dev/null

wait_ready() {
  endpoint=$1
  attempt=0
  until curl -fsS "$endpoint/health/ready" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    test "$attempt" -lt 80
    sleep 0.25
  done
}

primary_url="http://127.0.0.1:$primary_port"
wait_ready "$primary_url"
api_token=$(docker exec "$primary" sh -c 'cat /data/api.token')
test "${#api_token}" = "64"
docker exec "$primary" sh -c 'test "$(stat -c %a /data/api.token)" = "600"'
docker exec "$primary" sh -c 'grep -q "^Uid:[[:space:]]*10001" /proc/1/status && su-exec platform test -w /data && su-exec platform test ! -w /usr/local/bin'
curl -fsS "$primary_url/api/v1/setup/status" | grep -q '"initialized":false'
curl -fsS -X POST -H 'Content-Type: application/json' \
  -d '{"username":"container-admin","displayName":"容器管理员","password":"container-admin-password"}' \
  "$primary_url/api/v1/setup" | grep -q '"username":"container-admin"'
curl -fsS "$primary_url/api/v1/setup/status" | grep -q '"initialized":true'
login_headers="$artifact_dir/login-headers.txt"
login_cookies="$artifact_dir/login-cookies.txt"
curl -fsS -D "$login_headers" -c "$login_cookies" -X POST -H 'Content-Type: application/json' \
  -d '{"username":"container-admin","password":"container-admin-password"}' \
  "$primary_url/api/v1/auth/login" | grep -q '"username":"container-admin"'
if grep -i '^Set-Cookie:.*; Secure' "$login_headers" >/dev/null; then
  printf 'plain HTTP login incorrectly issued Secure cookies\n' >&2
  exit 1
fi
curl -fsS -b "$login_cookies" "$primary_url/api/v1/auth/me" | grep -q '"username":"container-admin"'
curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/meta" | grep -q '"schemaVersion":24'

settings_response="$artifact_dir/settings.json"
curl -fsS -X PUT -H "Authorization: Bearer $api_token" -H 'Content-Type: application/json' \
  -d '{"mfaEnabled":false,"mfaMethods":["totp"],"emailCodeTTL":"10m","mfaKeyFile":"/data/mfa.key","smtpHost":"","smtpPort":587,"smtpUsername":"","smtpPassword":"container-settings-test-secret","smtpFrom":"","tlsCertFile":"/cert/panel/fullchain.pem","tlsKeyFile":"/cert/panel/privkey.pem","accessTlsCertFile":"/cert/access/fullchain.pem","accessTlsKeyFile":"/cert/access/privkey.pem","httpPort":80,"httpsPort":443,"reusePanelPorts":true,"accessHttpPort":0,"accessHttpsPort":0,"panelDomain":"panel.container.example.test","accessDomain":"container-remote.example.test"}' \
  "$primary_url/api/v1/settings/security" -o "$settings_response"
grep -q '"restartRequired":true' "$settings_response"
if grep -q 'container-settings-test-secret' "$settings_response"; then
  printf 'SMTP password leaked into settings API response\n' >&2
  exit 1
fi
docker exec "$primary" sh -c 'test "$(stat -c %a /data/settings.override.conf)" = "600" && test "$(stat -c %a /data/smtp-password)" = "600" && ! grep -q container-settings-test-secret /data/settings.override.conf'

curl -fsS -H "Authorization: Bearer $api_token" -H 'Content-Type: application/json' \
  -d '{"name":"容器持久化验收节点","apiUrl":"https://127.0.0.1:16443","tlsServerName":"node.acceptance.local","credential":{"type":"session","username":"container-admin","password":"container-node-password"},"portStart":29000,"portEnd":29099}' \
  "$primary_url/api/v1/nodes" >/dev/null

docker stop -t 15 "$primary" >/dev/null
docker rm "$primary" >/dev/null
docker run -d --name "$primary" --restart no --security-opt no-new-privileges:true \
  -p "127.0.0.1:$primary_port:80" -p "127.0.0.1:$https_port:443" \
  -p "127.0.0.1:$access_http_port:28080" -p "127.0.0.1:$access_https_port:28443" \
  -e DMP_ACCESS_HTTP_PORT=28080 -e DMP_ACCESS_HTTPS_PORT=28443 \
  -v "$primary_volume:/data" -v "$certificate_volume:/cert:ro" "$image" >/dev/null
wait_ready "$primary_url"
curl -fsS --resolve "panel.container.example.test:$https_port:127.0.0.1" \
  --cacert "$artifact_dir/certificate-source/panel/fullchain.pem" \
  "https://panel.container.example.test:$https_port/health/ready" | grep -q '"status":"ready"'
access_route_one="device-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
access_route_two="device-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
access_route_three="device-cccccccccccccccccccccccccccccccc"
test "$(curl -sS -o /dev/null -w '%{http_code}' --resolve "$access_route_one.container-remote.example.test:$https_port:127.0.0.1" \
  --cacert "$artifact_dir/certificate-source/access/fullchain.pem" \
  "https://$access_route_one.container-remote.example.test:$https_port/")" = "401"
test "$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: $access_route_three.container-remote.example.test" \
  "http://127.0.0.1:$access_http_port/")" = "401"
test "$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: panel.container.example.test' "http://127.0.0.1:$access_http_port/")" = "404"
test "$(curl -sS -o /dev/null -w '%{http_code}' --resolve "$access_route_two.container-remote.example.test:$access_https_port:127.0.0.1" \
  --cacert "$artifact_dir/certificate-source/access/fullchain.pem" \
  "https://$access_route_two.container-remote.example.test:$access_https_port/")" = "401"
test "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/cert"}}{{.RW}}{{end}}{{end}}' "$primary")" = "false"
docker exec "$primary" sh -c 'su-exec platform test ! -r /cert/panel/fullchain.pem && su-exec platform test ! -r /cert/access/fullchain.pem && test ! -e /data/runtime-tls && test ! -e /run/device-management-platform/tls'
test "$(docker run --rm --entrypoint sh -v "$certificate_volume:/cert:ro" "$image" -c 'sha256sum /cert/panel/fullchain.pem /cert/panel/privkey.pem /cert/access/fullchain.pem /cert/access/privkey.pem')" = "$certificate_digest"
test "$(docker exec "$primary" sh -c 'cat /data/api.token')" = "$api_token"
curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/nodes" | grep -q '容器持久化验收节点'
curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/settings/security" | grep -q '"accessDomain":"container-remote.example.test"'
curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/settings/security" | grep -q '"accessTlsConfigured":true'
curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/settings/security" | grep -q '"restartRequired":false'
curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/settings/security" | grep -q '"accessHttpPort":28080'
curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/settings/security" | grep -q '"accessHttpsPort":28443'
curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/settings/security" | grep -q '"smtpPasswordConfigured":true'
https_headers="$artifact_dir/https-login-headers.txt"
curl -fsS --resolve "panel.container.example.test:$https_port:127.0.0.1" --cacert "$artifact_dir/certificate-source/panel/fullchain.pem" -D "$https_headers" -X POST -H 'Content-Type: application/json' \
  -d '{"username":"container-admin","password":"container-admin-password"}' \
  "https://panel.container.example.test:$https_port/api/v1/auth/login" >/dev/null
test "$(grep -ic '^Set-Cookie:.*; Secure' "$https_headers")" = "2"

curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/data/backup" -o "$artifact_dir/backup.db"
test "$(sqlite3 "$artifact_dir/backup.db" 'pragma integrity_check;')" = "ok"
test "$(sqlite3 "$artifact_dir/backup.db" 'select version from schema_migrations order by version desc limit 1;')" = "24"
docker volume create "$restored_volume" >/dev/null
docker run --rm -v "$restored_volume:/data" -v "$artifact_dir:/backup:ro" \
  "$image" restore /backup/backup.db >/dev/null
docker run -d --name "$restored" --restart no --security-opt no-new-privileges:true \
  -p "127.0.0.1:$restored_port:80" -v "$restored_volume:/data" "$image" >/dev/null
restored_url="http://127.0.0.1:$restored_port"
wait_ready "$restored_url"
restored_api_token=$(docker exec "$restored" sh -c 'cat /data/api.token')
test "${#restored_api_token}" = "64"
curl -fsS -H "Authorization: Bearer $restored_api_token" "$restored_url/api/v1/nodes" | grep -q '容器持久化验收节点'
curl -fsS -H "Authorization: Bearer $restored_api_token" "$restored_url/api/v1/meta" | grep -q '"schemaVersion":24'

printf 'Container acceptance passed\nbackup artifact: %s\n' "$artifact_dir/backup.db"
