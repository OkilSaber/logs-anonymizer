#!/bin/sh
# Construit l'AppImage Linux dans Docker, à partir du dernier commit (git archive HEAD) :
# le build ne voit que ce qui est versionné. Résultat : dist/linux/*.AppImage
#
#   packaging/linux/build.sh            # x86_64 (défaut)
#   packaging/linux/build.sh arm64
#
# Sur un Mac Apple Silicon, le build x86_64 passe par l'émulation : compter 20 à 40 minutes.
set -eu
cd "$(dirname "$0")/../.."
arch="${1:-amd64}"
image="logano-build:$arch"
docker build --platform "linux/$arch" -t "$image" packaging/linux
mkdir -p dist/linux
git archive --format=tar HEAD | docker run --rm -i --platform "linux/$arch" \
  -v "logano-cargo-$arch:/root/.cargo/registry" \
  -v "logano-target-$arch:/src/target" \
  -v "$(pwd)/dist/linux:/out" \
  "$image" sh -euc '
    tar -x -C /src
    cd /src/ui && npm ci
    cd /src/crates/app && CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_PROFILE_RELEASE_STRIP=symbols npx --yes @tauri-apps/cli@2 build --bundles appimage
    cp /src/target/release/bundle/appimage/*.AppImage /out/
  '
ls -la dist/linux
