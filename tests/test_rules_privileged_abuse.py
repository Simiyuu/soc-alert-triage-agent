from datetime import datetime, timezone
from typing import Optional
import pytest

from src.asset_registry import AssetIdentityRegistry
from src.models import (
    AssetContext,
    CriticalityLevel,
    EventType,
    UnifiedAuthRecord,
    UserContext,
    UserRole,
)
from src.rules_privileged_abuse import PrivilegedAccountAbuseRule


def make_record(
    timestamp: datetime,
    username: str,
    source_ip: str,
    hostname: str = "workstation-01",
    logon_type: Optional[int] = None,
    service: str = "windows_security",
    event_type: EventType = EventType.ACCEPTED_LOGIN,
) -> UnifiedAuthRecord:
    """Helper to construct standardized UnifiedAuthRecord instances for privilege abuse tests."""
    return UnifiedAuthRecord(
        timestamp=timestamp,
        hostname=hostname,
        service=service,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        port=445 if service == "windows_security" else 22,
        logon_type=logon_type,
    )


@pytest.fixture
def populated_registry() -> AssetIdentityRegistry:
    """Provides an AssetIdentityRegistry populated with test assets and privileged accounts."""
    reg = AssetIdentityRegistry()

    # Assets
    reg.register_asset(
        AssetContext(
            hostname="core-banking-db01",
            ip_address="10.100.4.50",
            criticality=CriticalityLevel.MISSION_CRITICAL,
            business_unit="Core Banking",
            is_crown_jewel=True,
        )
    )
    reg.register_asset(
        AssetContext(
            hostname="workstation-01",
            ip_address="10.10.1.25",
            criticality=CriticalityLevel.LOW,
            is_crown_jewel=False,
        )
    )

    # Identities
    reg.register_user(
        UserContext(
            username="svc_backup",
            role=UserRole.SERVICE_ACCOUNT,
            department="Infrastructure",
            approved_source_subnets=["10.100.4.0/24"],
        )
    )
    reg.register_user(
        UserContext(
            username="secops_admin",
            role=UserRole.PRIVILEGED_ADMIN,
            department="Security Operations",
            is_vip=True,
            approved_source_subnets=["192.168.10.0/24"],
        )
    )
    reg.register_user(
        UserContext(
            username="j_doe",
            role=UserRole.STANDARD,
            department="Finance",
            approved_source_subnets=[],
        )
    )

    return reg


@pytest.fixture
def abuse_rule(populated_registry: AssetIdentityRegistry) -> PrivilegedAccountAbuseRule:
    """Provides a PrivilegedAccountAbuseRule configured with business hours 06:00 to 20:00 UTC."""
    return PrivilegedAccountAbuseRule(
        registry=populated_registry,
        business_hours_start=6,
        business_hours_end=20,
    )


def test_interactive_service_account_logon_type_2_triggers_alert(abuse_rule: PrivilegedAccountAbuseRule):
    """Verify service account interactive logon (Type 2) triggers T1078.004 alert."""
    dt = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    record = make_record(
        timestamp=dt,
        username="svc_backup",
        source_ip="10.100.4.50",
        logon_type=2,
        hostname="workstation-01",
    )

    alert = abuse_rule.evaluate(record)
    assert alert is not None
    assert alert.mitre_technique == "T1078.004"
    assert alert.severity == "HIGH"
    assert any("interactive logon (Type 2)" in v for v in alert.metadata["violations"])


def test_interactive_service_account_rdp_type_10_triggers_alert(abuse_rule: PrivilegedAccountAbuseRule):
    """Verify service account RemoteInteractive (Type 10 RDP) triggers alert."""
    dt = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
    record = make_record(
        timestamp=dt,
        username="svc_backup",
        source_ip="10.100.4.50",
        logon_type=10,
        hostname="workstation-01",
    )

    alert = abuse_rule.evaluate(record)
    assert alert is not None
    assert alert.mitre_technique == "T1078.004"
    assert any("interactive logon (Type 10)" in v for v in alert.metadata["violations"])


def test_interactive_service_account_ssh_triggers_alert(abuse_rule: PrivilegedAccountAbuseRule):
    """Verify service account opening an interactive SSH session triggers alert."""
    dt = datetime(2026, 11, 1, 14, 0, 0, tzinfo=timezone.utc)
    record = make_record(
        timestamp=dt,
        username="svc_backup",
        source_ip="10.100.4.50",
        service="sshd",
        event_type=EventType.ACCEPTED_LOGIN,
        hostname="workstation-01",
    )

    alert = abuse_rule.evaluate(record)
    assert alert is not None
    assert alert.mitre_technique == "T1078.004"
    assert any("interactive SSH session" in v for v in alert.metadata["violations"])


def test_non_interactive_service_account_on_approved_subnet_is_benign(abuse_rule: PrivilegedAccountAbuseRule):
    """Verify non-interactive (Type 3 Network) service account logons from approved subnets pass clean."""
    dt = datetime(2026, 11, 1, 11, 0, 0, tzinfo=timezone.utc)
    record = make_record(
        timestamp=dt,
        username="svc_backup",
        source_ip="10.100.4.10",  # Inside approved 10.100.4.0/24
        logon_type=3,             # Network logon
        hostname="workstation-01",
    )

    alert = abuse_rule.evaluate(record)
    assert alert is None


def test_privileged_admin_unapproved_source_ip_triggers_alert(abuse_rule: PrivilegedAccountAbuseRule):
    """Verify admin login from unapproved subnet triggers T1078.002 alert."""
    dt = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    record = make_record(
        timestamp=dt,
        username="secops_admin",
        source_ip="203.0.113.88",  # Outside approved 192.168.10.0/24
        logon_type=2,
        hostname="workstation-01",
    )

    alert = abuse_rule.evaluate(record)
    assert alert is not None
    assert alert.mitre_technique == "T1078.002"
    assert any("unapproved source IP" in v for v in alert.metadata["violations"])


def test_privileged_admin_approved_source_business_hours_is_benign(abuse_rule: PrivilegedAccountAbuseRule):
    """Verify daytime admin access from approved subnet produces zero alerts."""
    dt = datetime(2026, 11, 1, 14, 30, 0, tzinfo=timezone.utc)
    record = make_record(
        timestamp=dt,
        username="secops_admin",
        source_ip="192.168.10.25",  # Inside approved 192.168.10.0/24
        logon_type=2,
        hostname="workstation-01",
    )

    alert = abuse_rule.evaluate(record)
    assert alert is None


def test_off_hours_access_to_crown_jewel_triggers_critical_alert(abuse_rule: PrivilegedAccountAbuseRule):
    """Verify off-hours access (02:00 UTC) to crown-jewel server escalates severity to CRITICAL."""
    dt = datetime(2026, 11, 1, 2, 0, 0, tzinfo=timezone.utc)  # Off-hours
    record = make_record(
        timestamp=dt,
        username="secops_admin",
        source_ip="192.168.10.25",  # Approved IP
        logon_type=2,
        hostname="core-banking-db01",  # Crown Jewel & MISSION_CRITICAL
    )

    alert = abuse_rule.evaluate(record)
    assert alert is not None
    assert alert.severity == "CRITICAL"
    assert any("Off-hours access" in v for v in alert.metadata["violations"])
    assert alert.metadata["is_crown_jewel"] is True


def test_multi_violation_escalates_to_critical(abuse_rule: PrivilegedAccountAbuseRule):
    """Verify multiple policy violations escalate alert severity to CRITICAL."""
    dt = datetime(2026, 11, 1, 1, 0, 0, tzinfo=timezone.utc)  # Off-hours
    record = make_record(
        timestamp=dt,
        username="svc_backup",
        source_ip="203.0.113.99",  # Unapproved IP + Interactive Type 2 + Off-hours
        logon_type=2,
        hostname="workstation-01",
    )

    alert = abuse_rule.evaluate(record)
    assert alert is not None
    assert alert.severity == "CRITICAL"
    assert len(alert.metadata["violations"]) >= 2


def test_standard_user_without_restrictions_passes_clean(abuse_rule: PrivilegedAccountAbuseRule):
    """Verify regular user logins do not trigger privilege abuse rules."""
    dt = datetime(2026, 11, 1, 23, 0, 0, tzinfo=timezone.utc)  # Off-hours
    record = make_record(
        timestamp=dt,
        username="j_doe",
        source_ip="172.16.1.50",
        logon_type=2,
        hostname="workstation-01",
    )

    alert = abuse_rule.evaluate(record)
    assert alert is None


def test_process_batch_evaluates_multiple_records(abuse_rule: PrivilegedAccountAbuseRule):
    """Verify process_batch filters and flags only non-compliant records."""
    dt_day = datetime(2026, 11, 1, 11, 0, 0, tzinfo=timezone.utc)
    records = [
        # Benign admin login
        make_record(dt_day, "secops_admin", "192.168.10.5", logon_type=2),
        # Abuse: interactive service account
        make_record(dt_day, "svc_backup", "10.100.4.50", logon_type=2),
    ]

    alerts = abuse_rule.process_batch(records)
    assert len(alerts) == 1
    assert alerts[0].target_users == ["svc_backup"]
    