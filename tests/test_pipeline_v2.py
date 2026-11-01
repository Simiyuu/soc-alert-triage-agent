from datetime import datetime, timezone
import pytest

from src.asset_registry import AssetIdentityRegistry
from src.models import (
    AssetContext,
    CriticalityLevel,
    EventType,
    SSHAuthEvent,
    TriageVerdict,
    UnifiedAuthRecord,
    UserContext,
    UserRole,
    WindowsAuthEvent,
)
from src.pipeline import TriagePipeline
from src.rules_password_spray import PasswordSprayRule
from src.rules_privileged_abuse import PrivilegedAccountAbuseRule


@pytest.fixture
def configured_pipeline() -> TriagePipeline:
    """Provides a fully configured TriagePipeline instance with registered assets and accounts."""
    registry = AssetIdentityRegistry()

    # Register assets
    registry.register_asset(
        AssetContext(
            hostname="core-vault01.corp",
            ip_address="10.100.4.50",
            criticality=CriticalityLevel.MISSION_CRITICAL,
            business_unit="Core Banking Operations",
            is_crown_jewel=True,
            environment="production",
        )
    )
    registry.register_asset(
        AssetContext(
            hostname="jump-box.corp",
            ip_address="192.168.10.10",
            criticality=CriticalityLevel.HIGH,
            business_unit="Security Operations",
            is_crown_jewel=False,
            environment="production",
        )
    )

    # Register identities
    registry.register_user(
        UserContext(
            username="svc_core_db",
            role=UserRole.SERVICE_ACCOUNT,
            department="Database Admin",
            approved_source_subnets=["10.100.4.0/24"],
        )
    )
    registry.register_user(
        UserContext(
            username="secops_lead",
            role=UserRole.PRIVILEGED_ADMIN,
            department="Information Security",
            is_vip=True,
            approved_source_subnets=["192.168.10.0/24"],
        )
    )

    spray_rule = PasswordSprayRule(
        user_threshold=3,
        window_seconds=120,
        alert_cooldown_seconds=60,
    )
    abuse_rule = PrivilegedAccountAbuseRule(
        registry=registry,
        business_hours_start=6,
        business_hours_end=20,
    )

    return TriagePipeline(
        registry=registry,
        spray_rule=spray_rule,
        abuse_rule=abuse_rule,
    )


def test_pipeline_normalizes_and_processes_ssh_events(configured_pipeline: TriagePipeline):
    """Verify raw SSHAuthEvents are normalized into UnifiedAuthRecords without schema errors."""
    now = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    ssh_event = SSHAuthEvent(
        timestamp=now,
        hostname="jump-box.corp",
        process_id=1234,
        event_type=EventType.ACCEPTED_LOGIN,
        username="secops_lead",
        source_ip="192.168.10.25",
        port=22,
        raw_log="Accepted publickey for secops_lead from 192.168.10.25 port 22 ssh2",
    )

    dossiers = configured_pipeline.process_event(ssh_event)
    # Authorized admin during daytime produces zero alerts
    assert len(dossiers) == 0


def test_pipeline_normalizes_and_processes_windows_events(configured_pipeline: TriagePipeline):
    """Verify raw WindowsAuthEvents are normalized and evaluated by rules."""
    now = datetime(2026, 11, 1, 14, 0, 0, tzinfo=timezone.utc)
    win_event = WindowsAuthEvent(
        timestamp=now,
        hostname="jump-box.corp",
        process_id=4,
        event_id=4624,
        event_type=EventType.ACCEPTED_LOGIN,
        username="secops_lead",
        source_ip="192.168.10.25",
        port=445,
        logon_type=2,
    )

    dossiers = configured_pipeline.process_event(win_event)
    assert len(dossiers) == 0


def test_pipeline_end_to_end_password_spray_detection(configured_pipeline: TriagePipeline):
    """Verify horizontal password spray generates a triaged dossier with containment commands."""
    base_time = 1700000000.0
    attacker_ip = "198.51.100.99"
    targeted_users = ["user_alpha", "user_beta", "user_gamma"]

    all_dossiers = []
    for idx, user in enumerate(targeted_users):
        event = UnifiedAuthRecord(
            timestamp=datetime.fromtimestamp(base_time + (idx * 5.0), tz=timezone.utc),
            hostname="jump-box.corp",
            service="sshd",
            event_type=EventType.FAILED_LOGIN,
            username=user,
            source_ip=attacker_ip,
            port=22,
        )
        dossiers = configured_pipeline.process_event(event)
        all_dossiers.extend(dossiers)

    # 3 distinct users triggers threshold (user_threshold=3)
    assert len(all_dossiers) == 1
    dossier = all_dossiers[0]

    assert dossier.alert.rule_name == "Password Spraying Detection"
    assert dossier.alert.mitre_technique == "T1110.003"
    assert dossier.alert.source_ip == attacker_ip
    assert dossier.assessment.risk_score >= 65.0
    assert dossier.containment_plan is not None
    assert any(attacker_ip in cmd for cmd in dossier.containment_plan.firewall_commands)


def test_pipeline_end_to_end_privileged_abuse_on_crown_jewel(configured_pipeline: TriagePipeline):
    """Verify service account off-hours interactive logon escalates to CRITICAL_CONTAINMENT."""
    off_hours_dt = datetime(2026, 11, 1, 2, 30, 0, tzinfo=timezone.utc)
    event = UnifiedAuthRecord(
        timestamp=off_hours_dt,
        hostname="core-vault01.corp",
        service="windows_security",
        event_type=EventType.ACCEPTED_LOGIN,
        username="svc_core_db",
        source_ip="203.0.113.88",  # Outside approved subnet + interactive Type 2 + off-hours + crown jewel
        port=445,
        logon_type=2,
    )

    dossiers = configured_pipeline.process_event(event)
    assert len(dossiers) == 1
    dossier = all_dossiers_item = dossiers[0]

    assert dossier.assessment.verdict == TriageVerdict.CRITICAL_CONTAINMENT
    assert dossier.assessment.requires_containment is True
    assert dossier.containment_plan is not None

    # Check that Active Directory lockout is compiled for svc_core_db
    assert any('Disable-ADAccount -Identity "svc_core_db"' in cmd for cmd in dossier.containment_plan.identity_actions)
    # Check that host isolation micro-segmentation is compiled for crown jewel
    assert len(dossier.containment_plan.host_isolation_commands) > 0

    # Verify Markdown generation succeeds and includes critical alert markers
    md = dossier.to_markdown()
    assert "CROWN JEWEL" in md
    assert "Disable-ADAccount" in md


def test_pipeline_batch_processing_and_risk_sorting(configured_pipeline: TriagePipeline):
    """Verify process_batch processes event sequences and orders dossiers by descending risk."""
    now = datetime(2026, 11, 1, 2, 0, 0, tzinfo=timezone.utc)

    # Event 1: Highly critical abuse on crown jewel
    ev_critical = UnifiedAuthRecord(
        timestamp=now,
        hostname="core-vault01.corp",
        service="windows_security",
        event_type=EventType.ACCEPTED_LOGIN,
        username="svc_core_db",
        source_ip="203.0.113.88",
        port=445,
        logon_type=2,
    )

    # Event 2, 3, 4: Password spray against jump host
    ev_spray_1 = UnifiedAuthRecord(
        timestamp=now,
        hostname="jump-box.corp",
        service="sshd",
        event_type=EventType.FAILED_LOGIN,
        username="acc_1",
        source_ip="198.51.100.5",
        port=22,
    )
    ev_spray_2 = UnifiedAuthRecord(
        timestamp=now,
        hostname="jump-box.corp",
        service="sshd",
        event_type=EventType.FAILED_LOGIN,
        username="acc_2",
        source_ip="198.51.100.5",
        port=22,
    )
    ev_spray_3 = UnifiedAuthRecord(
        timestamp=now,
        hostname="jump-box.corp",
        service="sshd",
        event_type=EventType.FAILED_LOGIN,
        username="acc_3",
        source_ip="198.51.100.5",
        port=22,
    )

    batch_dossiers = configured_pipeline.process_batch(
        [ev_spray_1, ev_spray_2, ev_critical, ev_spray_3]
    )

    assert len(batch_dossiers) == 2
    # The crown jewel attack should score higher than the jump box password spray
    assert batch_dossiers[0].assessment.risk_score >= batch_dossiers[1].assessment.risk_score
    assert batch_dossiers[0].assessment.verdict == TriageVerdict.CRITICAL_CONTAINMENT


def test_pipeline_state_querying_and_clearing(configured_pipeline: TriagePipeline):
    """Verify get_dossiers, get_critical_incidents, and clear manage operational queue."""
    now = datetime(2026, 11, 1, 2, 0, 0, tzinfo=timezone.utc)
    ev_crit = UnifiedAuthRecord(
        timestamp=now,
        hostname="core-vault01.corp",
        service="windows_security",
        event_type=EventType.ACCEPTED_LOGIN,
        username="svc_core_db",
        source_ip="203.0.113.88",
        port=445,
        logon_type=2,
    )
    configured_pipeline.process_event(ev_crit)

    assert len(configured_pipeline.get_dossiers()) == 1
    assert len(configured_pipeline.get_critical_incidents()) == 1

    configured_pipeline.clear()
    assert len(configured_pipeline.get_dossiers()) == 0
    assert len(configured_pipeline.get_critical_incidents()) == 0
    