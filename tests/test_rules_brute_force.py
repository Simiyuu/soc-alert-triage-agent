from datetime import datetime, timedelta, timezone
import pytest
from src.models import EventType, SecurityAlert, UnifiedAuthRecord
from src.rules import HorizontalPasswordSprayRule, VerticalBruteForceRule


def make_event(
    ip: str,
    user: str,
    ts: datetime,
    event_type: EventType = EventType.FAILED_LOGIN,
) -> UnifiedAuthRecord:
    return UnifiedAuthRecord(
        timestamp=ts,
        hostname="DC01.corp.internal",
        service="windows_security",
        event_type=event_type,
        username=user,
        source_ip=ip,
        port=445,
    )


def test_vertical_brute_force_triggers_above_threshold():
    """Verify 5 failed attempts against the same user within 60s triggers Vertical Brute Force."""
    rule = VerticalBruteForceRule(failure_threshold=5, window_seconds=60)
    base_time = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)
    alerts = []

    for i in range(5):
        event = make_event("198.51.100.50", "admin", base_time + timedelta(seconds=i * 5))
        alert = rule.evaluate(event)
        if alert:
            alerts.append(alert)

    assert len(alerts) == 1
    alert = alerts[0]
    assert isinstance(alert, SecurityAlert)
    assert alert.rule_id == "SOC-RULE-001"
    assert alert.rule_name == "Vertical Brute Force"
    assert alert.mitre_technique == "T1110.001"
    assert alert.severity == "HIGH"
    assert alert.source_ip == "198.51.100.50"
    assert alert.target_users == ["admin"]
    assert alert.event_count == 5


def test_vertical_brute_force_below_threshold_produces_no_alert():
    """Verify 4 failed attempts (threshold 5) produces no alert."""
    rule = VerticalBruteForceRule(failure_threshold=5, window_seconds=60)
    base_time = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)

    for i in range(4):
        event = make_event("198.51.100.50", "admin", base_time + timedelta(seconds=i * 5))
        alert = rule.evaluate(event)
        assert alert is None


def test_horizontal_password_spray_triggers_across_distinct_users():
    """Verify 1 IP hitting 5 distinct usernames within 300s triggers Horizontal Password Spray."""
    rule = HorizontalPasswordSprayRule(distinct_user_threshold=5, window_seconds=300)
    base_time = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)
    targets = ["finance_alice", "hr_bob", "eng_carol", "ops_david", "exec_eve"]
    alerts = []

    for idx, user in enumerate(targets):
        event = make_event("203.0.113.88", user, base_time + timedelta(seconds=idx * 15))
        alert = rule.evaluate(event)
        if alert:
            alerts.append(alert)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "SOC-RULE-002"
    assert alert.rule_name == "Horizontal Password Spray"
    assert alert.mitre_technique == "T1110.003"
    assert alert.severity == "CRITICAL"
    assert alert.source_ip == "203.0.113.88"
    assert set(alert.target_users) == set(targets)
    assert alert.event_count == 5


def test_horizontal_spray_same_user_repeated_does_not_trigger():
    """Verify multiple attempts against the same username do not trigger a horizontal spray."""
    rule = HorizontalPasswordSprayRule(distinct_user_threshold=5, window_seconds=300)
    base_time = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)

    # 5 attempts, but all targeting 'alice'
    for i in range(5):
        event = make_event("203.0.113.88", "alice", base_time + timedelta(seconds=i * 10))
        alert = rule.evaluate(event)
        assert alert is None