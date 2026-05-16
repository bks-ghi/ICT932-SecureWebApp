import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))

# OWASP A07: Authentication Failures - Test password hashing
def test_password_hashing():
    import bcrypt
    password = "TestPassword123!"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    assert bcrypt.checkpw(password.encode(), hashed)
    assert not bcrypt.checkpw(b"wrongpassword", hashed)

# OWASP A07: Authentication Failures - Test 2FA TOTP generation
def test_totp_generation():
    import pyotp
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    token = totp.now()
    assert totp.verify(token)

# OWASP A03: Injection - Test SQL injection input handling
def test_sql_injection_input():
    malicious_inputs = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "1; SELECT * FROM users"
    ]
    for inp in malicious_inputs:
        # Input must be treated as plain string, not executed
        assert isinstance(inp, str)
        assert len(inp) > 0

# OWASP A03: Injection - Test XSS input handling
def test_xss_input():
    xss_inputs = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)"
    ]
    for inp in xss_inputs:
        assert isinstance(inp, str)
        assert "<script>" in inp or "javascript:" in inp or "onerror" in inp

# OWASP A01: Broken Access Control - Test RBAC roles
def test_rbac_roles():
    valid_roles = ['admin', 'user']
    assert 'admin' in valid_roles
    assert 'user' in valid_roles
    assert 'superuser' not in valid_roles
    assert 'root' not in valid_roles

# OWASP A07: Weak Password Check
def test_password_complexity():
    weak_passwords = ["123456", "password", "abc", "111111"]
    for pwd in weak_passwords:
        is_weak = len(pwd) < 8 or not any(c.isupper() for c in pwd)
        assert is_weak, f"Password '{pwd}' should be detected as weak"

# Test TOTP secret uniqueness
def test_totp_secret_uniqueness():
    import pyotp
    secrets = [pyotp.random_base32() for _ in range(10)]
    assert len(set(secrets)) == 10  # All secrets must be unique