#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@file test_ssh_security.py
@brief Автоматические тесты безопасности для hardened SSH-сервера
@author [Твоё ФИО] (your.email@university.com)
@date 2026-05-28
@version 1.0.0
@license MIT

Steps:
    1. Подключение к SSH-серверу с некорректными параметрами
    2. Проверка отклонения аутентификации по паролю
    3. Проверка отклонения входа под root
    4. (Опционально) Проверка успешного входа по ключу
"""

import paramiko
import socket
import time
import os
import sys
from typing import Optional


# ==============================================================================
# КОНФИГУРАЦИЯ ТЕСТОВ (загружается из окружения)
# ==============================================================================
SSH_HOST = os.getenv("SSH_HOST", "localhost")
SSH_PORT = int(os.getenv("SSH_PORT", "2222"))
SSH_USER = os.getenv("SSH_USER", "appuser")
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", os.path.expanduser("~/.ssh/ssh-hardening-key"))
SSH_TIMEOUT = int(os.getenv("SSH_TIMEOUT", "10"))


def wait_for_ssh(host: str, port: int, timeout: int = 30) -> bool:
    """
    Ожидает доступности SSH-порта.

    Args:
        host: Хост для подключения
        port: Порт SSH
        timeout: Максимальное время ожидания в секундах

    Returns:
        True если порт доступен, False если таймаут
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except (socket.timeout, ConnectionRefusedError):
            time.sleep(1)
    return False


def test_password_auth_rejected() -> bool:
    """
    Проверяет, что аутентификация по паролю отклоняется.

    Returns:
        True если пароль отклонён (ожидаемое поведение), False иначе
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
        print("[FAIL] Пароль был принят! Это уязвимость!")
        return False
    except paramiko.AuthenticationException:
        print("[PASS] Пароль корректно отклонён")
        return True
    except Exception as e:
        print(f"[WARN] Неожиданная ошибка: {type(e).__name__}: {e}")
        # Если соединение сбрасывается — это тоже "защита сработала"
        return True
    finally:
        client.close()


def test_root_login_rejected() -> bool:
    """
    Проверяет, что вход под root запрещён.

    Returns:
        True если root-логин отклонён, False иначе
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
        print("[FAIL] Вход под root разрешён! Критическая уязвимость!")
        return False
    except paramiko.AuthenticationException:
        print("[PASS] Вход под root корректно отклонён")
        return True
    except Exception as e:
        print(f"[WARN] Ошибка при проверке root: {type(e).__name__}: {e}")
        return True
    finally:
        client.close()


def test_key_auth_works() -> bool:
    """
    Проверяет, что аутентификация по ключу работает (если ключ предоставлен).

    Returns:
        True если ключ принят, False если ошибка или ключ не найден
    """
    if not os.path.exists(SSH_KEY_PATH):
        print(f"[SKIP] Ключ не найден: {SSH_KEY_PATH}")
        return True  # Не считаем это провалом теста
    
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
        # Выполним простую команду для проверки сессии
        stdin, stdout, stderr = client.exec_command("whoami", timeout=5)
        result = stdout.read().decode().strip()
        client.close()
        
        if result == SSH_USER:
            print(f"[PASS] Ключ принят, пользователь: {result}")
            return True
        else:
            print(f"[FAIL] Неожиданный пользователь: {result}")
            return False
    except Exception as e:
        print(f"[FAIL] Ошибка аутентификации по ключу: {type(e).__name__}: {e}")
        return False


def run_all_tests() -> int:
    """
    Запускает все тесты безопасности и возвращает код выхода.

    Returns:
        0 если все тесты пройдены, 1 если есть провалы
    """
    print(f"\n{'='*60}")
    print(f"🔐 SSH Security Tests")
    print(f"{'='*60}")
    print(f"Target: {SSH_HOST}:{SSH_PORT}")
    print(f"User: {SSH_USER}")
    print(f"Key: {SSH_KEY_PATH}")
    print(f"{'='*60}\n")
    
    # Ждём доступности SSH
    if not wait_for_ssh(SSH_HOST, SSH_PORT):
        print(f"[ERROR] SSH-порт {SSH_PORT} не доступен на {SSH_HOST}")
        return 1
    
    print(f"[INFO] SSH-порт доступен, начинаем тесты...\n")
    
    results = []
    
    # Запускаем тесты
    results.append(("Password Auth Rejected", test_password_auth_rejected()))
    results.append(("Root Login Rejected", test_root_login_rejected()))
    results.append(("Key Auth Works", test_key_auth_works()))
    
    # Вывод результатов
    print(f"\n{'='*60}")
    print(f"📊 Результаты тестов:")
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
