import pytest
from src.sanitizer import sanitize_string, sanitize_auth_record
from src.models import EventType, UnifiedAuthRecord
from datetime import datetime, timezone


def test_sanitize_string_strips_ansi_escape_sequences():
    """Verify terminal escape codes (color codes, screen clears) are stripped."""
    malicious_user = "\x1b[31;1madmin\x1b[0m\x1b[2J"
    cleaned = sanitize_string(malicious_user)
    assert cleaned == "admin"


def test_sanitize_string_strips_null_bytes_and_unprintable_controls():
    """Verify null bytes and low control characters are purged."""
    malicious_user = "root\x00\x01\x02\x07_backdoor"
    cleaned = sanitize_string(malicious_user)
    assert cleaned == "root_backdoor"


def test_sanitize_string_prevents_log_forging_newlines():
    """Verify newlines and carriage returns (CWE-117) are replaced with spaces."""
    malicious_user = "admin\r\nOct 25 14:00:00 srv sshd[1]: Accepted password for root from 1.1.1.1"
    cleaned = sanitize_string(malicious_user)
    assert "\r" not in cleaned
    assert "\n" not in cleaned
    assert "admin Oct 25 14:00:00 srv sshd[1]: Accepted password for root from 1.1.1.1" in cleaned


def test_sanitize_string_unicode_nfkc_normalization():
    """Verify homoglyphs and decomposed unicode characters normalize to canonical forms."""
    # Decomposed 'e' + combining acute accent -> standard é
    decomposed = "caf\u0065\u0301"
    cleaned = sanitize_string(decomposed)
    assert cleaned == "café"


def test_sanitize_string_enforces_max_length_bound():
    """Verify oversized strings are truncated cleanly to protect memory and regex workers."""
    giant_string = "A" * 1024
    cleaned = sanitize_string(giant_string, max_length=128)
    assert len(cleaned) == 128
    assert cleaned == "A" * 128


def test_sanitize_auth_record_cleans_record_in_place():
    """Verify that a UnifiedAuthRecord has its username, hostname, and metadata sanitized."""
    record = UnifiedAuthRecord(
        timestamp=datetime.now(timezone.utc),
        hostname="bastion\x1b[31m-srv\r\n",
        service="sshd\x00",
        event_type=EventType.FAILED_LOGIN,
        username="admin\x00_test",
        source_ip="192.168.1.1",
        port=22,
        metadata={"client_agent": "evil\nagent"}
    )

    sanitized = sanitize_auth_record(record)
    assert sanitized.username == "admin_test"
    assert sanitized.hostname == "bastion-srv"
    assert sanitized.service == "sshd"
    assert sanitized.metadata["client_agent"] == "evil agent"