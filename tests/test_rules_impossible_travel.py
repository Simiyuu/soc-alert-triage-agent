from datetime import datetime, timedelta, timezone
import pytest
from src.models import EventType, SecurityAlert, UnifiedAuthRecord
from src.rules import ImpossibleTravelRule


def make_login(user: str, ip: str, ts: datetime) -> UnifiedAuthRecord:
    return UnifiedAuthRecord(
        timestamp=ts,
        hostname="vpn-gateway-01",
        service="sshd",
        event_type=EventType.ACCEPTED_LOGIN,
        username=user,
        source_ip=ip,
        port=22,
    )


def test_impossible_travel_triggers_across_continents():
    """Verify login in Nairobi followed by login in London 15 mins later triggers Impossible Travel."""
    rule = ImpossibleTravelRule(speed_threshold_kmh=800.0)
    t1 = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)
    t2 = t1 + timedelta(minutes=15)

    # Nairobi login
    e1 = make_login("alice", "197.237.100.1", t1)
    alert1 = rule.evaluate(e1)
    assert alert1 is None  # Baseline established

    # London login 15 minutes later
    e2 = make_login("alice", "81.2.69.142", t2)
    alert2 = rule.evaluate(e2)

    assert alert2 is not None
    assert isinstance(alert2, SecurityAlert)
    assert alert2.rule_id == "SOC-RULE-003"
    assert alert2.rule_name == "Impossible Travel"
    assert alert2.mitre_technique == "T1078"
    assert alert2.severity == "CRITICAL"
    assert alert2.target_users == ["alice"]
    assert alert2.metadata["origin_city"] == "Nairobi"
    assert alert2.metadata["target_city"] == "London"
    assert alert2.metadata["velocity_kmh"] > 25000.0


def test_legitimate_travel_duration_produces_no_alert():
    """Verify login in Nairobi followed by London 10 hours later (~682 km/h) produces no alert."""
    rule = ImpossibleTravelRule(speed_threshold_kmh=800.0)
    t1 = datetime(2026, 10, 25, 6, 0, 0, tzinfo=timezone.utc)
    t2 = t1 + timedelta(hours=10)

    e1 = make_login("bob", "197.237.100.1", t1)
    assert rule.evaluate(e1) is None

    e2 = make_login("bob", "81.2.69.142", t2)
    assert rule.evaluate(e2) is None


def test_failed_logins_ignored_by_impossible_travel():
    """Verify failed logins do not advance user location baseline."""
    rule = ImpossibleTravelRule(speed_threshold_kmh=800.0)
    t1 = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)
    t2 = t1 + timedelta(minutes=5)

    # Failed attempt from London should not trigger or update baseline
    failed_event = UnifiedAuthRecord(
        timestamp=t1,
        hostname="bastion-01",
        service="sshd",
        event_type=EventType.FAILED_LOGIN,
        username="charlie",
        source_ip="81.2.69.142",
        port=22,
    )
    assert rule.evaluate(failed_event) is None

    # Legitimate login from Nairobi
    e2 = make_login("charlie", "197.237.100.1", t2)
    assert rule.evaluate(e2) is None


def test_private_ips_do_not_trigger_impossible_travel():
    """Verify logins transitioning between internal RFC 1918 subnets do not raise false alerts."""
    rule = ImpossibleTravelRule(speed_threshold_kmh=800.0)
    t1 = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)
    t2 = t1 + timedelta(seconds=10)

    e1 = make_login("david", "10.0.0.5", t1)
    assert rule.evaluate(e1) is None

    e2 = make_login("david", "192.168.1.100", t2)
    assert rule.evaluate(e2) is None

