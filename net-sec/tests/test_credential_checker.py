import pytest
from app.audit.credential_checker import load_default_credentials

def test_load_default_credentials():
    creds = load_default_credentials()
    assert len(creds) >= 15
    pairs = set(creds)
    assert ("admin", "admin") in pairs
    assert ("admin", "123456") in pairs
    assert ("root", "xc3511") in pairs  # Mirai default
    assert ("root", "root") in pairs
