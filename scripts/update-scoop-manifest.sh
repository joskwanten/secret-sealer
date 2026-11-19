#!/usr/bin/env bash
# Points bucket/secret-sealer.json at a release: version, download URL and hash.
#
#   scripts/update-scoop-manifest.sh v1.2.3 dist/checksums.txt
set -euo pipefail

tag="${1:?gebruik: $0 <tag> <checksums.txt>}"
checksums="${2:?gebruik: $0 <tag> <checksums.txt>}"
manifest="$(dirname "$0")/../bucket/secret-sealer.json"
exe="secret-sealer-windows-amd64.exe"

hash="$(awk -v f="$exe" '$2 == f { print $1 }' "$checksums")"
[ -n "$hash" ] || { echo "Geen hash voor $exe in $checksums" >&2; exit 1; }

jq --arg version "${tag#v}" \
   --arg url "https://github.com/joskwanten/secret-sealer/releases/download/$tag/$exe#/secret-sealer.exe" \
   --arg hash "$hash" \
   '.version = $version | .architecture."64bit".url = $url | .architecture."64bit".hash = $hash' \
   "$manifest" > "$manifest.tmp"
mv "$manifest.tmp" "$manifest"
echo "bucket/secret-sealer.json → ${tag#v}"
