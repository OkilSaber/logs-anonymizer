#!/bin/sh
# Génère la paire de clés de test montée dans les deux conteneurs.
# La clé privée reste dans docker/keys/ (ignoré par git).
set -eu
dir="$(cd "$(dirname "$0")" && pwd)/keys"
mkdir -p "$dir"
if [ ! -f "$dir/id_test" ]; then
  ssh-keygen -q -t ed25519 -N "" -C "logano-docker-tests" -f "$dir/id_test"
fi
echo "Clé de test : $dir/id_test"
