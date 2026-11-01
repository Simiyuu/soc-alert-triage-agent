from datetime import datetime, timezone
import uuid
import pytest

from src.containment import ContainmentEngine, ContainmentPlan
from src.models import (
    AssetContext,
    CriticalityLevel,
    SecurityAlert,
    TriageAssessment,
    TriageVerdict,
    UserContext,
    UserRole,
)


def make_assessment(
    verdict: TriageVerdict = TriageVerdict.CRITICAL_CONTAINMENT,
    requires_containment: bool = True,
    risk_score: float = 90.0,
    asset: AssetContext = None,
    user: UserContext = None,
) -> TriageAssessment:
    """Helper to construct TriageAssessment instances for containment testing."""
    return TriageAssessment(
        alert_id=str(uuid.uuid4()),
        risk_score=risk_score,
        verdict=verdict,
        risk_factors=["High velocity attack", "Target is Crown Jewel"],
        mitre_tactics=["Credential Access", "Lateral Movement"],
        mitre_techniques=["T1110.003"],
        asset_context=asset,
        user_context=user,
        recommended_actions=["Contain source IP", "Lock account"],
        requires_containment=requires_containment,
    )


def make_alert(
    source_ip: str = "203.0.113.88",
    target_users: list = None,
) -> SecurityAlert:
    """Helper to construct SecurityAlert instances for containment testing."""
    now = datetime.now(timezone.utc)
    return SecurityAlert(
        rule_id="RULE-SPRAY-001",
        rule_name="Password Spray",
        mitre_technique="T1110.003",
        severity="CRITICAL",
        source_ip=source_ip,
        target_users=target_users or ["admin_user"],
        event_count=20,
        first_seen=now,
        last_seen=now,
    )


@pytest.fixture
def containment_engine() -> ContainmentEngine:
    """Provides a ContainmentEngine instance with default management CIDR."""
    return ContainmentEngine(management_cidr="10.50.0.0/24")


def test_containment_inactive_for_non_containment_verdicts(containment_engine: ContainmentEngine):
    """Verify assessments with requires_containment=False generate empty command sets."""
    assessment = make_assessment(
        verdict=TriageVerdict.SUSPICIOUS_REVIEW,
        requires_containment=False,
        risk_score=50.0,
    )

    plan = containment_engine.generate_plan(assessment, source_ip="198.51.100.1")
    assert plan.requires_containment is False
    assert plan.verdict == TriageVerdict.SUSPICIOUS_REVIEW
    assert len(plan.firewall_commands) == 0
    assert len(plan.identity_actions) == 0
    assert len(plan.host_isolation_commands) == 0
    assert any("No containment required" in s for s in plan.remediation_summary)


def test_firewall_commands_generation_for_attacker_ip(containment_engine: ContainmentEngine):
    """Verify perimeter and host firewall rules are compiled for target source IP."""
    assessment = make_assessment(requires_containment=True)
    plan = containment_engine.generate_plan(assessment, source_ip="198.51.100.200")

    assert plan.requires_containment is True
    assert plan.target_source_ip == "198.51.100.200"

    # Check iptables rule
    assert any("iptables -I INPUT -s 198.51.100.200 -j DROP" in cmd for cmd in plan.firewall_commands)
    # Check nftables rule
    assert any("nft add rule inet filter input ip saddr 198.51.100.200 counter drop" in cmd for cmd in plan.firewall_commands)
    # Check Windows Firewall PowerShell rule
    assert any("New-NetFirewallRule" in cmd and "198.51.100.200" in cmd for cmd in plan.firewall_commands)
    # Check Windows netsh fallback rule
    assert any("netsh advfirewall firewall add rule" in cmd and "198.51.100.200" in cmd for cmd in plan.firewall_commands)
    assert any("Perimeter/host firewall block generated" in s for s in plan.remediation_summary)


def test_identity_containment_actions_generation(containment_engine: ContainmentEngine):
    """Verify Active Directory and Linux account lockout syntax generation."""
    user = UserContext(
        username="compromised_admin",
        role=UserRole.PRIVILEGED_ADMIN,
        department="SecOps",
    )
    assessment = make_assessment(requires_containment=True, user=user)

    plan = containment_engine.generate_plan(assessment, source_ip="198.51.100.5")
    assert plan.target_username == "compromised_admin"

    # Active Directory lockout & token revocation
    assert any('Disable-ADAccount -Identity "compromised_admin"' in cmd for cmd in plan.identity_actions)
    assert any('Revoke-AzureADUserAllRefreshToken -ObjectId "compromised_admin"' in cmd for cmd in plan.identity_actions)

    # Linux local lockout & session termination
    assert any("passwd -l compromised_admin" in cmd for cmd in plan.identity_actions)
    assert any("pkill -KILL -u compromised_admin" in cmd for cmd in plan.identity_actions)
    assert any("Active Directory and local credential lockout" in s for s in plan.remediation_summary)


def test_crown_jewel_host_isolation_commands(containment_engine: ContainmentEngine):
    """Verify micro-segmentation rules preserve management CIDR for crown jewel hosts."""
    asset = AssetContext(
        hostname="core-swift-db01",
        ip_address="10.100.4.15",
        criticality=CriticalityLevel.MISSION_CRITICAL,
        is_crown_jewel=True,
    )
    assessment = make_assessment(requires_containment=True, asset=asset)

    plan = containment_engine.generate_plan(assessment, source_ip="198.51.100.99")
    assert plan.target_hostname == "core-swift-db01"
    assert len(plan.host_isolation_commands) > 0

    # Verify isolation drops standard traffic while whitelisting management subnet
    assert any("iptables -P INPUT DROP" in cmd for cmd in plan.host_isolation_commands)
    assert any("10.50.0.0/24" in cmd and "ACCEPT" in cmd for cmd in plan.host_isolation_commands)
    assert any("Set-NetFirewallProfile" in cmd for cmd in plan.host_isolation_commands)
    assert any("Network micro-segmentation / host isolation generated" in s for s in plan.remediation_summary)


def test_low_criticality_host_skips_isolation(containment_engine: ContainmentEngine):
    """Verify standard low-criticality workstations do not generate invasive host isolation rules."""
    asset = AssetContext(
        hostname="dev-workstation-20",
        criticality=CriticalityLevel.LOW,
        is_crown_jewel=False,
    )
    assessment = make_assessment(requires_containment=True, asset=asset)

    plan = containment_engine.generate_plan(assessment, source_ip="198.51.100.99")
    assert len(plan.host_isolation_commands) == 0


def test_target_resolution_from_alert_fallback(containment_engine: ContainmentEngine):
    """Verify IP and user targets resolve from SecurityAlert when absent in assessment context."""
    assessment = make_assessment(requires_containment=True, asset=None, user=None)
    alert = make_alert(source_ip="203.0.113.150", target_users=["fallback_target"])

    plan = containment_engine.generate_plan(assessment, alert=alert)
    assert plan.target_source_ip == "203.0.113.150"
    assert plan.target_username == "fallback_target"
    assert len(plan.firewall_commands) > 0
    assert len(plan.identity_actions) > 0


def test_unknown_targets_safely_ignored(containment_engine: ContainmentEngine):
    """Verify missing, anonymous, or unknown target values do not produce malformed commands."""
    user = UserContext(username="unknown", role=UserRole.STANDARD)
    assessment = make_assessment(requires_containment=True, user=user)

    plan = containment_engine.generate_plan(assessment, source_ip="unknown")
    assert len(plan.firewall_commands) == 0
    assert len(plan.identity_actions) == 0


def test_custom_management_cidr_propagation():
    """Verify custom management CIDR passes through to isolation rules."""
    engine = ContainmentEngine(management_cidr="172.16.99.0/24")
    asset = AssetContext(
        hostname="vault-server",
        criticality=CriticalityLevel.HIGH,
        is_crown_jewel=True,
    )
    assessment = make_assessment(requires_containment=True, asset=asset)

    plan = engine.generate_plan(assessment, source_ip="198.51.100.1")
    assert any("172.16.99.0/24" in cmd for cmd in plan.host_isolation_commands)
    