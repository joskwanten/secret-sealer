#!/usr/bin/env bash
# Builds the release binaries into dist/, plus checksums.txt.
#
#   scripts/build-release.sh v1.2.3
#
# Used by .github/workflows/release.yml; works the same on your own machine.
set -euo pipefail

version="${1:?gebruik: $0 <versie, bijv. v1.2.3>}"
cd "$(dirname "$0")/.."
rm -rf dist
mkdir -p dist

targets=(
  "windows amd64 secret-sealer-windows-amd64.exe"
  "darwin  arm64 secret-sealer-macos-arm64"
  "darwin  amd64 secret-sealer-macos-amd64"
  "linux   amd64 secret-sealer-linux-amd64"
  "linux   arm64 secret-sealer-linux-arm64"
)

for target in "${targets[@]}"; do
  read -r goos goarch name <<<"$target"
  echo "→ $name"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o "dist/$name" .
done

(cd dist && sha256sum secret-sealer-* > checksums.txt)
cat dist/checksums.txt
