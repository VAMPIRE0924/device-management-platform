#!/bin/sh
set -eu

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

echo "[1/4] backend race tests"
cd "$project_dir/backend"
go test -count=1 -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

echo "[2/4] frontend type, lint and contract tests"
cd "$project_dir/frontend"
npm run typecheck:spa
npm run lint
npm audit --audit-level=high
npm test
npm run build:spa

echo "[3/4] embedded single-binary build"
cd "$project_dir"
DMP_BUILD_VERSION="${DMP_BUILD_VERSION:-local}" ./scripts/build-local.sh
test "$(./backend/bin/device-management-platform version)" != "dev"

echo "[4/4] artifact checks"
test -x "$project_dir/backend/bin/device-management-platform"
test -s "$project_dir/backend/internal/ui/dist/index.html"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck "$project_dir/scripts/verify.sh" "$project_dir/scripts/build-local.sh" "$project_dir/scripts/acceptance-local.sh" "$project_dir/scripts/acceptance-container.sh"
fi
grep -qx 'secrets/\*' "$project_dir/.gitignore"
grep -qx 'secrets/\*' "$project_dir/.dockerignore"
grep -qx '/docs/' "$project_dir/.gitignore"
grep -qx 'docs' "$project_dir/.dockerignore"
test -z "$(git -C "$project_dir" ls-files docs scripts/verify-docs.sh)"

echo "Local verification passed"
