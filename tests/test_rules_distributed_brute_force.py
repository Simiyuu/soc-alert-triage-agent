from datetime import datetime, timedelta, timezone
import pytest
from src.models import EventType, SecurityAlert, UnifiedAuthRecord
from src.rules import DistributedBruteForceRule


def make_failed_event(ip: str, user: str, ts: datetime) -> UnifiedAuthRecord:
    return UnifiedAuthRecord(
        timestamp=ts,
        hostname="vpn-gateway-01",
        service="sshd",
        event_type=EventType.FAILED_LOGIN,
        username=user,
        source_ip=ip,
        port=22,
    )


def test_distributed_brute_force_triggers_across_distinct_ips():
    """Verify 5 distinct IPs targeting the same username within 120s triggers Distributed Brute Force."""
    rule = DistributedBruteForceRule(distinct_ip_threshold=5, window_seconds=120)
    base_time = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)
    ips = [
        "198.51.100.1",
        "198.51.100.2",
        "198.51.100.3",
        "198.51.100.4",
        "198.51.100.5",
    ]
    alerts = []

    for idx, ip in enumerate(ips):
        event = make_failed_event(ip, "svc_financials", base_time + timedelta(seconds=idx * 10))
        alert = rule.evaluate(event)
        if alert:
            alerts.append(alert)

    assert len(alerts) == 1
    alert = alerts[0]
    assert isinstance(alert, SecurityAlert)
    assert alert.rule_id == "SOC-RULE-004"
    assert alert.rule_name == "Distributed Multi-Source Brute Force"
    assert alert.mitre_technique == "T1110.004"
    assert alert.severity == "HIGH"
    assert alert.target_users == ["svc_financials"]
    assert alert.source_ip == "DISTRIBUTED"
    assert set(alert.metadata["source_ips"]) == set(ips)
    assert alert.event_count == 5


def test_repeated_attempts_from_same_ip_do_not_trigger_distributed_rule():
    """Verify multiple failures from fewer than 5 unique IPs do not satisfy the distinct IP requirement."""
    rule = DistributedBruteForceRule(distinct_ip_threshold=5, window_seconds=120)
    base_time = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)

    # 6 attempts total, but cycling only 2 distinct IPs
    for i in range(6):
        ip = "198.51.100.1" if i % 2 == 0 else "198.51.100.2"
        event = make_failed_event(ip, "svc_financials", base_time + timedelta(seconds=i * 5))
        alert = rule.evaluate(event)
        assert alert is None


def test_successful_logins_ignored_by_distributed_brute_force():
    """Verify accepted logins are skipped by brute force correlation."""
    rule = DistributedBruteForceRule(distinct_ip_threshold=3, window_seconds=120)
    base_time = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)

    accepted_event = UnifiedAuthRecord(
        timestamp=base_time,
        hostname="vpn-gateway-01",
        service="sshd",
        event_type=EventType.ACCEPTED_LOGIN,
        username="admin",
        source_ip="198.51.100.1",
        port=22,
    )
    assert rule.evaluate(accepted_event) is None
    