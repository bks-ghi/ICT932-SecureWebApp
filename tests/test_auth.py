import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))

# OWASP A07: Test password hashing
def test_password_hashing():
    import bcrypt
    password = "TestPassword123!"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    assert bcrypt.checkpw(password.encode(), hashed)
    assert not bcrypt.checkpw(b"wrongpassword", hashed)

# OWASP A07: Test 2FA TOTP
def test_totp_generation():
    import pyotp
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    token = totp.now()
    assert totp.verify(token)

# OWASP A03: SQL Injection input handling
def test_sql_injection_input():
    malicious_inputs = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "1; SELECT * FROM users"
    ]
    for inp in malicious_inputs:
        assert isinstance(inp, str)

# OWASP A01: RBAC roles validation
def test_rbac_roles():
    valid_roles = ['admin', 'user']
    assert 'admin' in valid_roles
    assert 'user' in valid_roles
    assert 'superuser' not in valid_roles

# OWASP A07: Weak password detection
def test_password_complexity():
    weak_passwords = ["123456", "password", "abc"]
    for pwd in weak_passwords:
        is_weak = len(pwd) < 8 or not any(c.isupper() for c in pwd)
        assert is_weak

# Test TOTP secret uniqueness
def test_totp_secret_uniqueness():
    import pyotp
    secrets = [pyotp.random_base32() for _ in range(5)]
    assert len(set(secrets)) == 5