# Image de build de l'AppImage Linux (Ubuntu 22.04 : glibc 2.35, WebKitGTK 4.1).
# Voir packaging/linux/build.sh.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake curl wget file ca-certificates pkg-config git xz-utils \
      libssl-dev libwebkit2gtk-4.1-dev libxdo-dev libayatana-appindicator3-dev librsvg2-dev libdbus-1-dev xdg-utils \
    && rm -rf /var/lib/apt/lists/*
# Node 22 (binaire officiel) et Rust stable.
RUN arch="$(dpkg --print-architecture)"; case "$arch" in amd64) n=x64;; arm64) n=arm64;; esac; \
    curl -fsSL "https://nodejs.org/dist/v22.11.0/node-v22.11.0-linux-$n.tar.xz" | tar -xJ -C /usr/local --strip-components=1
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH=/root/.cargo/bin:$PATH
# linuxdeploy et appimagetool sont des AppImage : sans FUSE dans un conteneur, on les extrait.
ENV APPIMAGE_EXTRACT_AND_RUN=1
WORKDIR /src
