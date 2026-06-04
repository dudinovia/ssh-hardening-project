#!/usr/bin/env bash
# @file entrypoint.sh
# @brief Инициализация защищённого SSH-сервера перед запуском демона
# @author [Твоё ФИО] (your.email@university.com)
# @date 2026-05-28
# @version 1.0.0
# @license MIT
#
# @details
#   1. Генерация host-ключей (если отсутствуют)
#   2. Создание баннера безопасности
#   3. Настройка прав доступа к конфигурациям
#   4. Запуск sshd в foreground-режиме

set -euo pipefail

log() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') | $1"
}

error() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') | $1" >&2
    exit 1
}

main() {
    log "Запуск инициализации SSH-сервера..."

    # Генерация host-ключей
    if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
        log "Генерация отсутствующих host-ключей..."
        ssh-keygen -A || error "Не удалось сгенерировать host-ключи"
    fi

    # Создание баннера
    cat > /etc/issue.net << 'BANNER'
***************************************************************************
                            SECURITY NOTICE
***************************************************************************
This system is restricted to authorized personnel only.
All connections are monitored and recorded.
Unauthorized access is prohibited and will be prosecuted.
***************************************************************************
BANNER
    chmod 644 /etc/issue.net

    # Фиксация прав (требование OpenSSH)
    local ssh_dir="/home/appuser/.ssh"
    if [[ -d "${ssh_dir}" ]]; then
        chmod 700 "${ssh_dir}"
        chmod 600 "${ssh_dir}/authorized_keys" 2>/dev/null || true
        chown -R appuser:appgroup "${ssh_dir}"
    fi

    log "Инициализация завершена. Передача управления sshd..."
    exec "$@"
}

main "$@"
