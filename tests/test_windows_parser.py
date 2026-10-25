from datetime import datetime, timezone
import pytest
from src.models import EventType, WindowsAuthEvent
from src.windows_parser import parse_windows_event


def test_parse_windows_4625_failed_password():
    """Verify Event ID 4625 with SubStatus 0xC000006A is normalized to FAILED_LOGIN."""
    raw_event = {
        "Event": {
            "System": {
                "EventID": 4625,
                "TimeCreated": {"SystemTime": "2026-10-25T14:30:00.000000Z"},
                "Computer": "DC01.corp.internal",
                "Execution": {"ProcessID": 648}
            },
            "EventData": {
                "TargetUserName": "svc_backup",
                "WorkstationName": "WS-FINANCE-04",
                "IpAddress": "10.100.4.52",
                "IpPort": "51234",
                "LogonType": 3,
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A"  # STATUS_PASSWORD_EXPIRED or bad password
            }
        }
    }

    event = parse_windows_event(raw_event)

    assert event is not None
    assert isinstance(event, WindowsAuthEvent)
    assert event.event_type == EventType.FAILED_LOGIN
    assert event.username == "svc_backup"
    assert str(event.source_ip) == "10.100.4.52"
    assert event.port == 51234
    assert event.logon_type == 3
    assert event.hostname == "DC01.corp.internal"
    assert event.sub_status == "0xC000006A"
    assert event.timestamp == datetime(2026, 10, 25, 14, 30, 0, tzinfo=timezone.utc)


def test_parse_windows_4625_invalid_user():
    """Verify Event ID 4625 with SubStatus 0xC0000064 maps to INVALID_USER."""
    raw_event = {
        "Event": {
            "System": {
                "EventID": 4625,
                "TimeCreated": {"SystemTime": "2026-10-25T14:31:15.500000Z"},
                "Computer": "DC01.corp.internal",
                "Execution": {"ProcessID": 648}
            },
            "EventData": {
                "TargetUserName": "nonexistent_admin",
                "WorkstationName": "UNKNOWN",
                "IpAddress": "198.51.100.20",
                "IpPort": "49152",
                "LogonType": 3,
                "Status": "0xC000006D",
                "SubStatus": "0xC0000064"  # STATUS_NO_SUCH_USER
            }
        }
    }

    event = parse_windows_event(raw_event)

    assert event is not None
    assert event.event_type == EventType.INVALID_USER
    assert event.username == "nonexistent_admin"
    assert str(event.source_ip) == "198.51.100.20"


def test_parse_windows_4624_rdp_successful_logon():
    """Verify Event ID 4624 with LogonType 10 (RemoteInteractive/RDP) is normalized to ACCEPTED_LOGIN."""
    raw_event = {
        "Event": {
            "System": {
                "EventID": 4624,
                "TimeCreated": {"SystemTime": "2026-10-25T14:35:00.123000Z"},
                "Computer": "APP-SRV-01.corp.internal",
                "Execution": {"ProcessID": 712}
            },
            "EventData": {
                "TargetUserName": "admin_jdoe",
                "WorkstationName": "LAPTOP-JDOE",
                "IpAddress": "10.200.1.15",
                "IpPort": "3389",
                "LogonType": 10,
                "Status": "0x0"
            }
        }
    }

    event = parse_windows_event(raw_event)

    assert event is not None
    assert event.event_type == EventType.ACCEPTED_LOGIN
    assert event.username == "admin_jdoe"
    assert event.logon_type == 10
    assert str(event.source_ip) == "10.200.1.15"


def test_parse_windows_local_logon_dash_ip_returns_none():
    """Verify console logons where IpAddress is '-' (no network socket) are safely discarded or handled."""
    raw_event = {
        "Event": {
            "System": {
                "EventID": 4624,
                "TimeCreated": {"SystemTime": "2026-10-25T14:40:00Z"},
                "Computer": "DC01.corp.internal",
                "Execution": {"ProcessID": 648}
            },
            "EventData": {
                "TargetUserName": "SYSTEM",
                "WorkstationName": "-",
                "IpAddress": "-",
                "IpPort": "-",
                "LogonType": 0
            }
        }
    }

    event = parse_windows_event(raw_event)
    # Network telemetry correlation requires a valid routable IP; local dash entries are safely filtered
    assert event is None


def test_parse_windows_unrelated_event_id_returns_none():
    """Verify non-auth Windows events (e.g. Process Creation 4688) return None."""
    raw_event = {
        "Event": {
            "System": {
                "EventID": 4688,
                "TimeCreated": {"SystemTime": "2026-10-25T14:41:00Z"},
                "Computer": "DC01.corp.internal",
                "Execution": {"ProcessID": 4}
            },
            "EventData": {
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe"
            }
        }
    }

    event = parse_windows_event(raw_event)
    assert event is None