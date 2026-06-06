import pytest
import paramiko
import time

SSH_HOST = "localhost"
SSH_PORT = 2222

def test_password_auth_disabled():
    """
    Проверяет, что при попытке входа по паролю для пользователя
    (даже существующего) сервер отклоняет аутентификацию (PasswordAuthentication no).
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    with pytest.raises(paramiko.ssh_exception.AuthenticationException):
        # Попытка авторизации с паролем. Должно выбросить AuthenticationException
        # так как сервер разрешает только ключи (и MFA).
        client.connect(
            hostname=SSH_HOST,
            port=SSH_PORT,
            username="appuser",
            password="SecurePassword123!",
            timeout=5
        )
    client.close()

def test_root_login_disabled():
    """
    Проверяет, что вход под пользователем root строго запрещен (PermitRootLogin no).
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    with pytest.raises(paramiko.ssh_exception.AuthenticationException):
        # Попытка авторизации root, даже с каким-то паролем или пустым.
        client.connect(
            hostname=SSH_HOST,
            port=SSH_PORT,
            username="root",
            password="somepassword",
            timeout=5
        )
    client.close()

def test_mfa_required_after_key():
    """
    Проверяет, что при предъявлении правильного ключа сервер запрашивает MFA (keyboard-interactive).
    Даже с правильным ключом мы должны получить AuthenticationException, если не введем OTP.
    """
    import os
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    key_path = os.path.join(os.path.dirname(__file__), "..", "deploy", "ssh-keys", "test_client_key")
    
    if not os.path.exists(key_path):
        pytest.skip(f"Test key not found at {key_path}. Run bootstrap.sh first.")
        
    with pytest.raises(paramiko.ssh_exception.AuthenticationException) as excinfo:
        # Пробуем подключиться только с ключом, без указания обработчика MFA.
        # Сервер должен отклонить auth, так как нужно 2 фактора.
        client.connect(
            hostname=SSH_HOST,
            port=SSH_PORT,
            username="appuser",
            key_filename=key_path,
            timeout=5
        )
    
    # Опционально можно проверить, что в логах или ошибке указан partial auth,
    # но paramiko выбрасывает общий AuthenticationException. Главное, что нас не пустило!
    client.close()
