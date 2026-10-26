from datetime import datetime, timezone
import pytest
from src.ingest import stream_unified_events
from src.models import EventType, UnifiedAuthRecord


def test_stream_unified_events_from_heterogeneous_inputs():
    """Verify stream_unified_events handles mixed Linux and Windows raw telemetry."""
    mixed_payloads = [
        "Oct 25 14:02:10 srv-prod-01 sshd[10442]: Failed password for root from 192.168.1.100 port 22 ssh2",
        {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "TimeCreated": {"SystemTime": "2026-10-25T14:05:00.000000Z"},
                    "Computer": "DC01.corp.internal",
                    "Execution": {"ProcessID": 648}
                },
                "EventData": {
                    "TargetUserName": "admin_jdoe",
                    "WorkstationName": "LAPTOP-JDOE",
                    "IpAddress": "10.200.1.15",
                    "IpPort": "3389",
                    "LogonType": 10
                }
            }
        },
        "Oct 25 14:06:12 srv-prod-01 sshd[10445]: Accepted password for ubuntu from 192.168.1.105 port 45222 ssh2",
        "Corrupted non-auth syslog line that should be silently dropped",
        {
            "Event": {
                "System": {"EventID": 4688},
                "EventData": {"NewProcessName": "cmd.exe"}
            }
        }
    ]

    events = list(stream_unified_events(mixed_payloads))

    assert len(events) == 3

    # Event 1: Linux SSH Failed Login
    assert isinstance(events[0], UnifiedAuthRecord)
    assert events[0].service == "sshd"
    assert events[0].username == "root"
    assert events[0].event_type == EventType.FAILED_LOGIN
    assert str(events[0].source_ip) == "192.168.1.100"

    # Event 2: Windows 4624 Accepted Login
    assert isinstance(events[1], UnifiedAuthRecord)
    assert events[1].service == "windows_security"
    assert events[1].username == "admin_jdoe"
    assert events[1].event_type == EventType.ACCEPTED_LOGIN
    assert str(events[1].source_ip) == "10.200.1.15"

    # Event 3: Linux SSH Accepted Login
    assert isinstance(events[2], UnifiedAuthRecord)
    assert events[2].service == "sshd"
    assert events[2].username == "ubuntu"
    assert events[2].event_type == EventType.ACCEPTED_LOGIN


def test_stream_unified_events_generator_is_lazy():
    """Verify that stream_unified_events produces a memory-efficient generator."""
    payloads = ["Oct 25 14:02:10 srv-prod-01 sshd[10442]: Failed password for root from 192.168.1.100 port 22 ssh2"]
    gen = stream_unified_events(payloads)
    
    # Assert generator type (not loaded list)
    assert hasattr(gen, "__iter__")
    assert hasattr(gen, "__next__")
    first = next(gen)
    assert first.username == "root"
    