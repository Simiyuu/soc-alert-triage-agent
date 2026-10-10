import pytest
from datetime import datetime
from src.parser import parse_line
from src.models import EventType


def test_parse_failed_password_valid_user():
    line = "Oct  6 22:15:08 bastion-host sshd[14205]: Failed password for ubuntu from 192.168.1.105 port 45218 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == EventType.FAILED_LOGIN
    assert event.username == "ubuntu"
    assert str(event.source_ip) == "192.168.1.105"
    assert event.port == 45218
    assert event.process_id == 14205
    assert event.hostname == "bastion-host"
    assert event.timestamp == datetime(2026, 10, 6, 22, 15, 8)


def test_parse_failed_password_invalid_user():
    line = "Oct  6 22:15:01 bastion-host sshd[14201]: Failed password for invalid user admin from 192.168.1.105 port 45212 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == EventType.INVALID_USER
    assert event.username == "admin"
    assert str(event.source_ip) == "192.168.1.105"


def test_parse_accepted_password():
    line = "Oct  6 22:16:12 bastion-host sshd[14220]: Accepted password for deployer from 10.0.0.15 port 51230 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == EventType.ACCEPTED_LOGIN
    assert event.username == "deployer"
    assert str(event.source_ip) == "10.0.0.15"


def test_parse_unrelated_syslog_returns_none():
    line = "Oct  6 22:17:00 bastion-host CRON[14250]: (root) CMD (/usr/local/bin/backup.sh)"
    assert parse_line(line) is None


def test_parse_empty_string_returns_none():
    assert parse_line("") is None
    assert parse_line("   \n") is None