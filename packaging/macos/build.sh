#!/bin/sh
# Construit l'application macOS universelle (Apple Silicon + Intel) et son .dmg.
# Résultat : target/universal-apple-darwin/release/bundle/{macos,dmg}/
#
# Prérequis : Xcode Command Line Tools, Rust avec les deux cibles
# (rustup target add aarch64-apple-darwin x86_64-apple-darwin), Node 20+, cargo-tauri 2.
set -eu
cd "$(dirname "$0")/../.."
(cd ui && npm ci)
# Binaire distribué : sans symboles de debug, et sans les chemins de la machine de build.
export CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_PROFILE_RELEASE_STRIP=symbols
export RUSTFLAGS="--remap-path-prefix=$HOME=/build --remap-path-prefix=$(pwd)=/build/logs-anonymizer"
cd crates/app
cargo tauri build --target universal-apple-darwin --bundles app,dmg
