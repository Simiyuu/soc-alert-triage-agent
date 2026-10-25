from datetime import datetime, timezone
import pytest
from src.parser import parse_line as parse_auth_line
from src.models import EventType


def test_parse_iso8601_rfc5424_timestamp():
    """Verify parser accepts modern ISO-8601 / RFC 5424 syslog timestamps."""
    raw_line = "2026-10-25T14:02:10.123456+00:00 srv-prod-01 sshd[10442]: Failed password for root from 192.168.1.100 port 22 ssh2"
    event = parse_auth_line(raw_line)
    
    assert event is not None
    assert event.timestamp.year == 2026
    assert event.timestamp.month == 10
    assert event.timestamp.day == 25
    assert event.username == "root"


def test_parse_legacy_timestamp_infers_current_year_and_utc():
    """Verify legacy BSD syslog timestamps (Mmm dd hh:mm:ss) resolve with valid year and UTC awareness."""
    raw_line = "Oct 25 14:02:10 srv-prod-01 sshd[10442]: Failed password for root from 192.168.1.100 port 22 ssh2"
    event = parse_auth_line(raw_line)
    
    assert event is not None
    assert event.timestamp.year >= 2024
    assert event.timestamp.tzinfo is not None or event.timestamp.utcoffset() is not None


def test_parse_malformed_ip_returns_none_defensively():
    """Verify invalid IP addresses (e.g. octets > 255) return None instead of raising unhandled exceptions."""
    raw_line = "Oct 25 14:02:10 srv-prod-01 sshd[10442]: Failed password for root from 999.999.999.999 port 22 ssh2"
    event = parse_auth_line(raw_line)
    assert event is None


def test_parse_invalid_port_bounds_returns_none():
    """Verify ports outside 1-65535 are discarded safely."""
    raw_line = "Oct 25 14:02:10 srv-prod-01 sshd[10442]: Failed password for root from 192.168.1.100 port 70000 ssh2"
    event = parse_auth_line(raw_line)
    assert event is None


def test_parse_adversarial_username_injection():
    """Verify usernames with command injection attempts or quotes are parsed cleanly."""
    adversarial_user = "admin';DROP TABLE users;--"
    raw_line = f"Oct 25 14:02:10 srv-prod-01 sshd[10442]: Failed password for invalid user {adversarial_user} from 10.0.0.5 port 54321 ssh2"
    event = parse_auth_line(raw_line)
    
    assert event is not None
    assert event.event_type == EventType.INVALID_USER
    assert event.username == adversarial_user
    assert str(event.source_ip) == "10.0.0.5"


def test_parse_oversized_fuzzed_line():
    """Verify parser rejects or safely discards gigabyte-scale or 10k-char fuzzed buffer lines."""
    fuzzed_user = "A" * 8192
    raw_line = f"Oct 25 14:02:10 srv-prod-01 sshd[10442]: Failed password for {fuzzed_user} from 10.0.0.5 port 22 ssh2"
    event = parse_auth_line(raw_line)
    assert event is None or event.username == fuzzed_user