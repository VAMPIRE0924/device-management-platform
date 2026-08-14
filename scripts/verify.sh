#!/bin/sh
set -eu

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

echo "[1/5] documentation"
"$project_dir/scripts/verify-docs.sh"

echo "[2/5] backend race tests"
cd "$project_dir/backend"
go test -count=1 -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

echo "[3/5] frontend type, lint and contract tests"
cd "$project_dir/frontend"
npm run typecheck:spa
npm run lint
npm audit --audit-level=high
npm test
npm run build:spa

echo "[4/5] embedded single-binary build"
cd "$project_dir"
I5CLOUD_BUILD_VERSION="${I5CLOUD_BUILD_VERSION:-local}" ./scripts/build-local.sh
test "$(./backend/bin/i5cloud version)" != "dev"

echo "[5/5] artifact checks"
test -x "$project_dir/backend/bin/i5cloud"
test -s "$project_dir/backend/internal/ui/dist/index.html"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck "$project_dir/scripts/verify.sh" "$project_dir/scripts/verify-docs.sh" "$project_dir/scripts/build-local.sh" "$project_dir/scripts/acceptance-local.sh" "$project_dir/scripts/acceptance-container.sh"
fi
grep -qx 'secrets/\*' "$project_dir/.gitignore"
grep -qx '!secrets/README.md' "$project_dir/.gitignore"
grep -qx 'secrets/\*' "$project_dir/.dockerignore"
grep -qx '!secrets/README.md' "$project_dir/.dockerignore"

echo "I5CLOUD local verification passed"
