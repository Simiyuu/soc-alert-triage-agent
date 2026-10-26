from datetime import datetime, timedelta, timezone
import pytest
from src.deduplicator import AlertDeduplicator
from src.models import SecurityAlert


def make_alert(
    rule_id: str = "SOC-RULE-001",
    rule_name: str = "Vertical Brute Force",
    ip: str = "198.51.100.50",
    users: list[str] = None,
    ts: datetime = None,
) -> SecurityAlert:
    if users is None:
        users = ["admin"]
    if ts is None:
        ts = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)

    return SecurityAlert(
        rule_id=rule_id,
        rule_name=rule_name,
        mitre_technique="T1110.001",
        severity="HIGH",
        source_ip=ip,
        target_users=users,
        event_count=5,
        first_seen=ts - timedelta(seconds=30),
        last_seen=ts,
    )


def test_deduplicator_emits_first_alert():
    """Verify first occurrence of an alert passes through immediately."""
    dedup = AlertDeduplicator(suppression_window_seconds=600)
    alert = make_alert()
    
    result = dedup.process(alert)
    assert result is not None
    assert result.rule_id == "SOC-RULE-001"
    assert dedup.is_suppressed(alert) is True


def test_deduplicator_suppresses_subsequent_duplicate_alerts():
    """Verify identical alerts within the suppression window return None."""
    dedup = AlertDeduplicator(suppression_window_seconds=600)
    t0 = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)
    
    alert1 = make_alert(ts=t0)
    alert2 = make_alert(ts=t0 + timedelta(seconds=60))
    alert3 = make_alert(ts=t0 + timedelta(seconds=120))

    assert dedup.process(alert1) is not None
    assert dedup.process(alert2) is None
    assert dedup.process(alert3) is None
    assert dedup.get_suppressed_count(alert1) == 2


def test_deduplicator_rearms_after_window_expires():
    """Verify an alert re-emits after the suppression window passes and includes suppressed count."""
    dedup = AlertDeduplicator(suppression_window_seconds=300)
    t0 = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)

    alert1 = make_alert(ts=t0)
    alert2 = make_alert(ts=t0 + timedelta(seconds=60))  # Suppressed
    alert3 = make_alert(ts=t0 + timedelta(seconds=360)) # Window expired (t=360s > 300s)

    assert dedup.process(alert1) is not None
    assert dedup.process(alert2) is None
    
    rearmed = dedup.process(alert3)
    assert rearmed is not None
    assert rearmed.metadata.get("suppressed_occurrences") == 1


def test_distinct_alerts_not_suppressed():
    """Verify alerts with different IPs or rules do not collide."""
    dedup = AlertDeduplicator(suppression_window_seconds=600)
    t0 = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)

    alert_ip1 = make_alert(ip="198.51.100.50", ts=t0)
    alert_ip2 = make_alert(ip="198.51.100.99", ts=t0 + timedelta(seconds=10))

    assert dedup.process(alert_ip1) is not None
    assert dedup.process(alert_ip2) is not None
    