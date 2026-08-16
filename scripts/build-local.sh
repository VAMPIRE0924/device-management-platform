#!/bin/sh
set -eu

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ui_target="$project_dir/backend/internal/ui/dist"
output_dir="$project_dir/backend/bin"
build_version="${DMP_BUILD_VERSION:-local}"

case "$ui_target" in
  "$project_dir/backend/internal/ui/dist") ;;
  *) echo "refusing unexpected UI target: $ui_target" >&2; exit 1 ;;
esac

cd "$project_dir/frontend"
npm run build:spa

find "$ui_target" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
cp -R "$project_dir/frontend/dist-spa/." "$ui_target/"

mkdir -p "$output_dir"
cd "$project_dir/backend"
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$build_version" -o "$output_dir/device-management-platform" ./cmd/server
echo "built $output_dir/device-management-platform"
