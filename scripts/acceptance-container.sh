#!/bin/sh
set -eu

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
run_id="$(date +%s)-$$"
image="i5cloud/remote-management:container-acceptance"
primary="i5cloud-acceptance-$run_id"
restored="i5cloud-restored-$run_id"
primary_volume="i5cloud-acceptance-data-$run_id"
restored_volume="i5cloud-restored-data-$run_id"
primary_port="${I5CLOUD_CONTAINER_ACCEPTANCE_PORT:-18090}"
restored_port="${I5CLOUD_CONTAINER_RESTORE_PORT:-18091}"
api_token="container-acceptance-api-token-0123456789abcdef"
setup_token="container-acceptance-setup-token-0123456789"
restored_api_token="container-restored-api-token-0123456789abcdef"
restored_setup_token="container-restored-setup-token-0123456789"
artifact_dir=$(mktemp -d /tmp/i5cloud-container-acceptance.XXXXXX)

cleanup() {
  docker rm -f "$primary" "$restored" >/dev/null 2>&1 || true
  docker volume rm "$primary_volume" "$restored_volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

command -v docker >/dev/null
command -v curl >/dev/null
command -v sqlite3 >/dev/null
docker info >/dev/null

docker build --build-arg VERSION=container-acceptance -t "$image" "$project_dir"
if docker scout version >/dev/null 2>&1; then
  docker scout cves "$image" --only-severity critical,high --exit-code
else
  printf 'Docker Scout unavailable; image CVE scan skipped\n' >&2
fi
docker volume create "$primary_volume" >/dev/null
docker run -d --name "$primary" --restart no --cap-drop ALL --security-opt no-new-privileges:true \
  -p "127.0.0.1:$primary_port:8088" -v "$primary_volume:/data" \
  -e I5CLOUD_API_TOKEN="$api_token" -e I5CLOUD_SETUP_TOKEN="$setup_token" "$image" >/dev/null

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
test "$(docker inspect "$primary" --format '{{.Config.User}}')" = "i5cloud:i5cloud"
docker exec "$primary" sh -c 'test "$(id -u)" = "10001" && test -w /data && test ! -w /usr/local/bin'
curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/meta" | grep -q '"schemaVersion":21'

settings_response="$artifact_dir/settings.json"
curl -fsS -X PUT -H "Authorization: Bearer $api_token" -H 'Content-Type: application/json' \
  -d '{"mfaEnabled":false,"mfaMethods":["totp"],"emailCodeTTL":"10m","mfaKeyFile":"/data/mfa.key","smtpHost":"","smtpPort":587,"smtpUsername":"","smtpPassword":"container-settings-test-secret","smtpFrom":"","tlsCertFile":"","tlsKeyFile":"","accessDomain":"container-remote.example.test"}' \
  "$primary_url/api/v1/settings/security" -o "$settings_response"
grep -q '"restartRequired":true' "$settings_response"
if grep -q 'container-settings-test-secret' "$settings_response"; then
  printf 'SMTP password leaked into settings API response\n' >&2
  exit 1
fi
docker exec "$primary" sh -c 'test "$(stat -c %a /data/i5cloud.override.conf)" = "600" && test "$(stat -c %a /data/i5cloud.smtp-password)" = "600" && ! grep -q container-settings-test-secret /data/i5cloud.override.conf'

curl -fsS -H "Authorization: Bearer $api_token" -H 'Content-Type: application/json' \
  -d '{"name":"容器持久化验收节点","apiUrl":"https://127.0.0.1:16443","tlsServerName":"node.acceptance.local","credential":{"type":"session","username":"container-admin","password":"container-node-password"},"portStart":29000,"portEnd":29099}' \
  "$primary_url/api/v1/nodes" >/dev/null

docker stop -t 15 "$primary" >/dev/null
docker rm "$primary" >/dev/null
docker run -d --name "$primary" --restart no --cap-drop ALL --security-opt no-new-privileges:true \
  -p "127.0.0.1:$primary_port:8088" -v "$primary_volume:/data" \
  -e I5CLOUD_API_TOKEN="$api_token" -e I5CLOUD_SETUP_TOKEN="$setup_token" "$image" >/dev/null
wait_ready "$primary_url"
curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/nodes" | grep -q '容器持久化验收节点'
curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/settings/security" | grep -q '"accessDomain":"container-remote.example.test"'
curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/settings/security" | grep -q '"restartRequired":false'
curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/settings/security" | grep -q '"smtpPasswordConfigured":true'

curl -fsS -H "Authorization: Bearer $api_token" "$primary_url/api/v1/data/backup" -o "$artifact_dir/backup.db"
test "$(sqlite3 "$artifact_dir/backup.db" 'pragma integrity_check;')" = "ok"
test "$(sqlite3 "$artifact_dir/backup.db" 'select version from schema_migrations order by version desc limit 1;')" = "21"
docker volume create "$restored_volume" >/dev/null
docker run --rm -v "$restored_volume:/data" -v "$artifact_dir:/backup:ro" \
  -e I5CLOUD_API_TOKEN="$restored_api_token" -e I5CLOUD_SETUP_TOKEN="$restored_setup_token" \
  "$image" restore /backup/backup.db >/dev/null
docker run -d --name "$restored" --restart no --cap-drop ALL --security-opt no-new-privileges:true \
  -p "127.0.0.1:$restored_port:8088" -v "$restored_volume:/data" \
  -e I5CLOUD_API_TOKEN="$restored_api_token" -e I5CLOUD_SETUP_TOKEN="$restored_setup_token" "$image" >/dev/null
restored_url="http://127.0.0.1:$restored_port"
wait_ready "$restored_url"
curl -fsS -H "Authorization: Bearer $restored_api_token" "$restored_url/api/v1/nodes" | grep -q '容器持久化验收节点'
curl -fsS -H "Authorization: Bearer $restored_api_token" "$restored_url/api/v1/meta" | grep -q '"schemaVersion":21'

printf 'I5CLOUD container acceptance passed\nbackup artifact: %s\n' "$artifact_dir/backup.db"
