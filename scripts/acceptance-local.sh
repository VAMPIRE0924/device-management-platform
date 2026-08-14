#!/bin/sh
set -eu

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
binary="$project_dir/backend/bin/i5cloud"
acceptance_dir=$(mktemp -d /tmp/i5cloud-acceptance.XXXXXX)
acceptance_port="${I5CLOUD_ACCEPTANCE_PORT:-18089}"
acceptance_url="http://127.0.0.1:$acceptance_port"
api_token="local-acceptance-api-token-0123456789abcdef"
setup_token="local-acceptance-setup-token-0123456789"
server_pid=""

stop_server() {
  if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
    kill -TERM "$server_pid"
    wait "$server_pid" || true
  fi
}
trap stop_server EXIT INT TERM

test -x "$binary"
command -v curl >/dev/null
command -v sqlite3 >/dev/null

I5CLOUD_MODE=pro \
I5CLOUD_LISTEN_ADDR="127.0.0.1:$acceptance_port" \
I5CLOUD_DATA_DIR="$acceptance_dir" \
I5CLOUD_DB_PATH="$acceptance_dir/i5cloud.db" \
I5CLOUD_API_TOKEN="$api_token" \
I5CLOUD_SETUP_TOKEN="$setup_token" \
I5CLOUD_COOKIE_SECURE=false \
"$binary" serve >"$acceptance_dir/server.log" 2>&1 &
server_pid=$!

attempt=0
until curl -fsS "$acceptance_url/health/ready" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 40 ]; then
    printf 'server did not become ready; log: %s\n' "$acceptance_dir/server.log" >&2
    exit 1
  fi
  sleep 0.1
done

curl -fsS "$acceptance_url/health/live" >/dev/null
curl -fsS "$acceptance_url/health/ready" >/dev/null
meta=$(curl -fsS -H "Authorization: Bearer $api_token" "$acceptance_url/api/v1/meta")
printf '%s' "$meta" | grep -q '"mode":"pro"'
printf '%s' "$meta" | grep -q '"schemaVersion":21'

unauthorized=$(curl -sS -o "$acceptance_dir/unauthorized.json" -w '%{http_code}' "$acceptance_url/api/v1/nodes")
unknown=$(curl -sS -o "$acceptance_dir/unknown.json" -w '%{http_code}' -H "Authorization: Bearer $api_token" "$acceptance_url/api/v1/not-a-route")
test "$unauthorized" = "401"
test "$unknown" = "404"

curl -fsS -H "Authorization: Bearer $api_token" "$acceptance_url/api/v1/data/backup" -o "$acceptance_dir/backup.db"
test "$(sqlite3 "$acceptance_dir/backup.db" 'pragma integrity_check;')" = "ok"
test "$(sqlite3 "$acceptance_dir/backup.db" 'select version from schema_migrations order by version desc limit 1;')" = "21"

stop_server
server_pid=""
printf 'I5CLOUD local black-box acceptance passed\nartifacts: %s\n' "$acceptance_dir"
