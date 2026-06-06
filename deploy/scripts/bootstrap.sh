#!/usr/bin/env bash
# @file bootstrap.sh
# @brief Скрипт первичной подготовки хоста и запуска SSH-инфраструктуры
# @author [Твоё ФИО] (your.email@university.com)
# @date 2026-05-30
# @version 1.0.0
# @license MIT
#
# @details
#   1. Проверка прав root/sudo
#   2. Применение настроек ядра (sysctl)
#   3. Базовая настройка UFW (опционально)
#   4. Запуск Docker Compose

set -euo pipefail

log() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') | $1"
}

error() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') | $1" >&2
    exit 1
}

main() {
    log "Запуск bootstrap-скрипта для SSH Hardening проекта..."

    # 1. Проверка прав
    if [[ $EUID -ne 0 ]]; then
       error "Этот скрипт требует прав root (запустите через sudo)."
    fi

    # 2. Применение настроек ядра
    log "Применение sysctl-настроек из config/sysctl.d/..."
    # Ищем папку config относительно места запуска скрипта или корня проекта
    local script_dir
    script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
    local project_root
    project_root="$(dirname "$(dirname "$script_dir")")"
    
    if [[ -f "${project_root}/config/sysctl.d/99-hardening.conf" ]]; then
        sysctl -p "${project_root}/config/sysctl.d/99-hardening.conf" || error "Ошибка применения sysctl"
        log "Sysctl настройки применены."
    else
        log "WARN: Файл sysctl.conf не найден, пропускаем."
    fi

    # 3. Запуск контейнеров
    log "Переход к запуску Docker Compose..."
    cd "${project_root}/deploy" || error "Не удалось найти папку deploy"
    
    docker compose down -v || true
    docker compose up -d --build
    
    log "Инфраструктура запущена!"
    log "Проверьте статус: docker compose ps"
}

main "$@"
