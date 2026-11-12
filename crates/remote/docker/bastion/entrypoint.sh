#!/bin/sh
set -eu
if [ ! -f /keys/id_test.pub ]; then
  echo "Clé absente : lancer docker/gen-keys.sh avant docker compose up" >&2
  exit 1
fi
ssh-keygen -A
install -d -m 700 -o jump -g jump /home/jump/.ssh
install -m 600 -o jump -g jump /keys/id_test.pub /home/jump/.ssh/authorized_keys
exec /usr/sbin/sshd -D -e
