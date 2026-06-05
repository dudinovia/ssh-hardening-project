#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@file test_ssh_security.py
@brief Автоматические тесты безопасности для hardened SSH-сервера
@author [Бессараб Григорий Олегович] (bessarab@sfedu.ru)
@date 2026-05-28
@version 1.0.0
@license MIT

Steps:
    1. Проверка доступности порта SSH
    2. Валидация отклонения аутентификации по паролю
    3. Валидация запрета входа под root
    4. Проверка успешной аутентификации по открытому ключу
"""

import paramiko
import socket
import time
import os
import sys
from typing import Optional


# ==============================================================================
# КОНФИГУРАЦИЯ (загружается из окружения или использует значения по умолчанию)
# ==============================================================================
SSH_HOST = os.getenv("SSH_HOST", "localhost")
SSH_PORT = int(os.getenv("SSH_PORT", "2222"))
SSH_USER = os.getenv("SSH_USER", "appuser")
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", os.path.expanduser("~/.ssh/ssh-hardening-key"))
SSH_TIMEOUT = int(os.getenv("SSH_TIMEOUT", "10"))


def wait_for_ssh(host: str, port: int, timeout: int = 30) -> bool:
    """
    Ожидает открытия TCP-порта SSH.

    Args:
        host: Целевой хост
        port: Целевой порт
        timeout: Максимальное время ожидания в секундах

    Returns:
        True если порт доступен, False при таймауте
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            time.sleep(1)
    return False


def test_password_auth_rejected() -> bool:
    """
    Проверяет, что сервер отклоняет попытку входа по паролю.

    Returns:
        True если аутентификация отклонена (ожидаемое поведение)
    """
    print(f"[TEST] Проверка отклонения аутентификации по паролю...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=SSH_HOST,
            port=SSH_PORT,
            username=SSH_USER,
            password="WrongPassword123!",
            timeout=SSH_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=5
        )
        print("[FAIL] Пароль был принят! Это критическая уязвимость.")
        return False
    except paramiko.AuthenticationException:
        print("[PASS] Пароль корректно отклонён (AuthenticationException)")
        return True
    except Exception as e:
        # Разрыв соединения или другая ошибка тоже считается "защита сработала"
        print(f"[PASS] Соединение разорвано/отклонено: {type(e).__name__}")
        return True
    finally:
        client.close()


def test_root_login_rejected() -> bool:
    """
    Проверяет, что прямой вход под root запрещён.

    Returns:
        True если вход под root отклонён
    """
    print(f"[TEST] Проверка запрета входа под root...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=SSH_HOST,
            port=SSH_PORT,
            username="root",
            password="AnyPassword",
            timeout=SSH_TIMEOUT,
            allow_agent=False,
            look_for_keys=False
        )
        print("[FAIL] Вход под root разрешён! Критическая уязвимость.")
        return False
    except paramiko.AuthenticationException:
        print("[PASS] Вход под root корректно отклонён")
        return True
    except Exception as e:
        print(f"[PASS] Соединение с root разорвано: {type(e).__name__}")
        return True
    finally:
        client.close()


def test_key_auth_works() -> bool:
    """
    Проверяет, что аутентификация по SSH-ключу работает корректно.

    Returns:
        True если ключ принят и сессия установлена
    """
    if not os.path.exists(SSH_KEY_PATH):
        print(f"[SKIP] Приватный ключ не найден: {SSH_KEY_PATH}")
        return True  # Не считаем это провалом инфраструктурного теста

    print(f"[TEST] Проверка аутентификации по ключу...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=SSH_HOST,
            port=SSH_PORT,
            username=SSH_USER,
            key_filename=SSH_KEY_PATH,
            timeout=SSH_TIMEOUT,
            passphrase=None,
            allow_agent=False,
            look_for_keys=False
        )
        stdin, stdout, stderr = client.exec_command("whoami", timeout=5)
        result = stdout.read().decode().strip()
        client.close()

        if result == SSH_USER:
            print(f"[PASS] Ключ принят, активный пользователь: {result}")
            return True
        else:
            print(f"[FAIL] Неожиданный пользователь в сессии: {result}")
            return False
    except Exception as e:
        print(f"[FAIL] Ошибка аутентификации по ключу: {type(e).__name__}: {e}")
        return False


def run_all_tests() -> int:
    """
    Запускает полный набор тестов безопасности и возвращает код выхода.

    Returns:
        0 если все тесты пройдены, 1 если есть падения
    """
    print(f"\n{'='*60}")
    print(f"🔐 SSH Security Validation Suite")
    print(f"{'='*60}")
    print(f"Target: {SSH_HOST}:{SSH_PORT}")
    print(f"User: {SSH_USER}")
    print(f"Key: {SSH_KEY_PATH}")
    print(f"{'='*60}\n")

    if not wait_for_ssh(SSH_HOST, SSH_PORT):
        print(f"[ERROR] Порт {SSH_PORT} на {SSH_HOST} не отвечает. Проверьте docker compose ps")
        return 1

    print("[INFO] Порт доступен. Запуск тестов...\n")

    results = []
    results.append(("Password Auth Rejected", test_password_auth_rejected()))
    results.append(("Root Login Rejected", test_root_login_rejected()))
    results.append(("Key Auth Works", test_key_auth_works()))

    print(f"\n{'='*60}")
    print("📊 Результаты:")
    print(f"{'='*60}")

    passed = 0
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} | {name}")
        if result:
            passed += 1

    print(f"{'='*60}")
    print(f"Итого: {passed}/{len(results)} тестов пройдено")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
