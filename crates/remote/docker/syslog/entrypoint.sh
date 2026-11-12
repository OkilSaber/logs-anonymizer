#!/bin/sh
# Prépare les comptes et l'arborescence de logs, puis lance sshd.
# Le contenu des fichiers est repris tel quel dans tests/docker_ssh.rs.
set -eu
if [ ! -f /keys/id_test.pub ]; then
  echo "Clé absente : lancer docker/gen-keys.sh avant docker compose up" >&2
  exit 1
fi
ssh-keygen -A
for user in logs logspw; do
  install -d -m 700 -o "$user" -g "$user" "/home/$user/.ssh"
  install -m 600 -o "$user" -g "$user" /keys/id_test.pub "/home/$user/.ssh/authorized_keys"
done

apps=/srv/syslog/2026/11/09/APPS
mkdir -p \
  "$apps/etam_sb_gateway/etam-sb" \
  "$apps/jar_sb_admin/jar-sb-atlas" \
  "$apps/jar_sb_admin/jar-sb-atlas02" \
  /srv/syslog/2026/11/09/SYSTEM/host01

printf 'gateway ligne 1\ngateway ligne 2\n' | gzip -c > "$apps/etam_sb_gateway/etam-sb/erlang.log.gz"
printf 'haproxy gateway\n' | gzip -c > "$apps/etam_sb_gateway/etam-sb/haproxy.log.gz"
printf 'atlas ligne 1\natlas ligne 2\natlas ligne 3\n' > "$apps/jar_sb_admin/jar-sb-atlas/erlang.log"
printf 'atlas02\n' | gzip -c > "$apps/jar_sb_admin/jar-sb-atlas02/erlang.log.gz"

chown -R syslog:logreader-tenant /srv/syslog
find /srv/syslog -type d -exec chmod 755 {} +
find /srv/syslog -type f -exec chmod 640 {} +

exec /usr/sbin/sshd -D -e
