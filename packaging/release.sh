#!/bin/sh
# Rassemble les fichiers d'une release dans dist/release/ et écrit latest.json, que l'app
# lit pour savoir s'il existe une version plus récente.
#
#   packaging/macos/build.sh && packaging/linux/build.sh && packaging/release.sh
#   gh release create "v<version>" dist/release/* --title ... --notes ...
#
# Les noms sont ceux que GitHub donne aux fichiers (les espaces deviennent des points).
set -eu
cd "$(dirname "$0")/.."
version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
repo="${LOGANO_REPO:-OkilSaber/logs-anonymizer}"
base="https://github.com/$repo/releases/download/v$version"
mac="target/universal-apple-darwin/release/bundle"
out="dist/release"
rm -rf "$out" && mkdir -p "$out"

cp "$mac/dmg/Logs Anonymizer_${version}_universal.dmg" "$out/Logs.Anonymizer_${version}_universal.dmg"
cp "$mac/macos/Logs Anonymizer.app.tar.gz" "$out/Logs.Anonymizer_${version}_universal.app.tar.gz"
cp "dist/linux/Logs Anonymizer_${version}_amd64.AppImage" "$out/Logs.Anonymizer_${version}_amd64.AppImage"
mac_sig="$(cat "$mac/macos/Logs Anonymizer.app.tar.gz.sig")"
linux_sig="$(cat "dist/linux/Logs Anonymizer_${version}_amd64.AppImage.sig")"

# Les trois plateformes : le paquet macOS est universel, il sert les deux architectures.
printf '%s\n' \
  '{' \
  "  \"version\": \"$version\"," \
  "  \"notes\": \"${LOGANO_NOTES:-Voir les notes de la release $version.}\"," \
  "  \"pub_date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," \
  '  "platforms": {' \
  "    \"darwin-aarch64\": { \"signature\": \"$mac_sig\", \"url\": \"$base/Logs.Anonymizer_${version}_universal.app.tar.gz\" }," \
  "    \"darwin-x86_64\": { \"signature\": \"$mac_sig\", \"url\": \"$base/Logs.Anonymizer_${version}_universal.app.tar.gz\" }," \
  "    \"linux-x86_64\": { \"signature\": \"$linux_sig\", \"url\": \"$base/Logs.Anonymizer_${version}_amd64.AppImage\" }" \
  '  }' \
  '}' > "$out/latest.json"
ls -la "$out"
