FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo gzip findutils coreutils \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && groupadd logreader-tenant \
 && (id syslog >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin syslog) \
 && useradd -m -s /bin/bash logs \
 && useradd -m -s /bin/bash logspw \
 && echo 'logs:mot-de-passe-inutilise' | chpasswd \
 && echo 'logspw:logano-sudo-pw' | chpasswd \
 && printf 'logs ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/logs \
 && printf 'Defaults:logspw timestamp_timeout=0\nlogspw ALL=(ALL) ALL\n' > /etc/sudoers.d/logspw \
 && chmod 440 /etc/sudoers.d/logs /etc/sudoers.d/logspw

COPY sshd_logano.conf /etc/ssh/sshd_config.d/logano.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
