# @file Dockerfile
# @brief Многоэтапная сборка защищённого SSH-сервера (OpenSSH)
# @version 1.0.0

FROM debian:12-slim AS base

LABEL maintainer="your.email@university.com"
LABEL description="Hardened SSH Server with MFA support"
LABEL version="1.0.0"

ENV DEBIAN_FRONTEND=noninteractive \
    SSH_PORT=2222 \
    RUNLEVEL=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        sudo \
        wget \
        curl \
        nano \
        htop \
        net-tools \
        ca-certificates \
        apt-transport-https \
        netcat-openbsd \
        dos2unix \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

FROM base AS mfa-enabled

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpam-google-authenticator \
    && rm -rf /var/lib/apt/lists/*

FROM mfa-enabled AS final

RUN groupadd -g 1000 appgroup && \
    useradd -u 1000 -g appgroup -m -s /bin/bash appuser && \
    echo "appuser:SecurePassword123!" | chpasswd && \
    echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

RUN useradd -m -s /bin/bash testuser || true

#COPY ../config/sshd_config /etc/ssh/sshd_config

RUN chmod 600 /etc/ssh/sshd_config && \
    mkdir -p /home/appuser/.ssh && \
    chown -R appuser:appgroup /home/appuser/.ssh && \
    chmod 700 /home/appuser/.ssh

COPY docker/ssh-server/scripts/entrypoint.sh /entrypoint.sh
RUN dos2unix /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE ${SSH_PORT}

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nc -z localhost ${SSH_PORT} || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
