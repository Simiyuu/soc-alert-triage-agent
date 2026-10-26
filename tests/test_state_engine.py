from datetime import datetime, timedelta, timezone
import pytest
from src.models import EventType, UnifiedAuthRecord
from src.state_engine import SlidingWindowStateTracker


def create_record(ip: str, user: str, ts: datetime, event_type: EventType = EventType.FAILED_LOGIN) -> UnifiedAuthRecord:
    return UnifiedAuthRecord(
        timestamp=ts,
        hostname="bastion-01",
        service="sshd",
        event_type=event_type,
        username=user,
        source_ip=ip,
        port=22,
    )


def test_sliding_window_tracks_and_counts_events():
    """Verify state tracker correctly appends and counts events within active window."""
    tracker = SlidingWindowStateTracker(window_seconds=60)
    base_time = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # 3 failures for 192.168.1.5 within 30 seconds
    for offset in [0, 10, 20]:
        event = create_record("192.168.1.5", "admin", base_time + timedelta(seconds=offset))
        tracker.add_event(key=str(event.source_ip), event=event)

    events_in_window = tracker.get_events(key="192.168.1.5", current_time=base_time + timedelta(seconds=30))
    assert len(events_in_window) == 3
    assert tracker.get_count(key="192.168.1.5", current_time=base_time + timedelta(seconds=30)) == 3


def test_sliding_window_evicts_stale_events():
    """Verify events older than window_seconds are automatically purged."""
    tracker = SlidingWindowStateTracker(window_seconds=60)
    base_time = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # Event at t=0s
    e1 = create_record("10.0.0.1", "root", base_time)
    tracker.add_event(key="10.0.0.1", event=e1)

    # Event at t=30s
    e2 = create_record("10.0.0.1", "root", base_time + timedelta(seconds=30))
    tracker.add_event(key="10.0.0.1", event=e2)

    # Check at t=70s: e1 (70s old) must be evicted; e2 (40s old) must remain
    current_time = base_time + timedelta(seconds=70)
    active_events = tracker.get_events(key="10.0.0.1", current_time=current_time)
    
    assert len(active_events) == 1
    assert active_events[0].timestamp == base_time + timedelta(seconds=30)
    assert tracker.get_count(key="10.0.0.1", current_time=current_time) == 1


def test_sliding_window_distinct_user_aggregation():
    """Verify aggregation of unique usernames hit by a single source IP within a window."""
    tracker = SlidingWindowStateTracker(window_seconds=300)
    base_time = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # 1 IP targeting 4 different users
    users = ["alice", "bob", "charlie", "david"]
    for idx, u in enumerate(users):
        event = create_record("198.51.100.2", u, base_time + timedelta(seconds=idx * 10))
        tracker.add_event(key="198.51.100.2", event=event)

    current_time = base_time + timedelta(seconds=60)
    distinct_users = tracker.get_distinct_field_values(key="198.51.100.2", field_name="username", current_time=current_time)
    
    assert len(distinct_users) == 4
    assert set(distinct_users) == {"alice", "bob", "charlie", "david"}


def test_empty_or_expired_key_cleanup():
    """Verify keys with no remaining active events are pruned from internal dict."""
    tracker = SlidingWindowStateTracker(window_seconds=30)
    base_time = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    event = create_record("10.10.10.10", "root", base_time)
    tracker.add_event(key="10.10.10.10", event=event)

    # At t=100s, window is entirely expired
    current_time = base_time + timedelta(seconds=100)
    active = tracker.get_events(key="10.10.10.10", current_time=current_time)
    assert len(active) == 0
    assert tracker.active_keys_count() == 0
    