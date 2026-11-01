from datetime import datetime, timedelta, timezone
from typing import List, Optional
import pytest

from src.asset_registry import AssetIdentityRegistry
from src.models import (
    AssetContext,
    CriticalityLevel,
    SecurityAlert,
    TriageVerdict,
    UserContext,
    UserRole,
)
from src.risk_engine import RiskEngine
from src.triage_engine import TriageEngine


def make_alert(
    severity: str = "MEDIUM",
    source_ip: str = "192.168.1.100",
    target_users: Optional[List[str]] = None,
    event_count: int = 1,
    mitre_technique: str = "T1110.003",
    target_hostname: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> SecurityAlert:
    """Helper to build standardized SecurityAlert instances for triage testing."""
    now = datetime.now(timezone.utc)
    meta = metadata.copy() if metadata else {}
    if target_hostname:
        meta["target_hostname"] = target_hostname

    return SecurityAlert(
        rule_id="RULE-TRIAGE-001",
        rule_name="Authentication Anomaly",
        mitre_technique=mitre_technique,
        severity=severity,
        source_ip=source_ip,
        target_users=target_users or ["regular_user"],
        event_count=event_count,
        first_seen=now - timedelta(minutes=5),
        last_seen=now,
        metadata=meta,
    )


@pytest.fixture
def populated_registry() -> AssetIdentityRegistry:
    """Provides an AssetIdentityRegistry populated with test assets and accounts."""
    reg = AssetIdentityRegistry()

    reg.register_asset(
        AssetContext(
            hostname="core-vault01.corp",
            ip_address="10.100.4.50",
            criticality=CriticalityLevel.MISSION_CRITICAL,
            business_unit="Core Banking",
            is_crown_jewel=True,
        )
    )
    reg.register_asset(
        AssetContext(
            hostname="web-front01.corp",
            ip_address="172.16.1.10",
            criticality=CriticalityLevel.MEDIUM,
            is_crown_jewel=False,
        )
    )

    reg.register_user(
        UserContext(
            username="secops_admin",
            role=UserRole.PRIVILEGED_ADMIN,
            is_vip=True,
        )
    )
    reg.register_user(
        UserContext(
            username="regular_user",
            role=UserRole.STANDARD,
            is_vip=False,
        )
    )

    return reg


@pytest.fixture
def triage_engine(populated_registry: AssetIdentityRegistry) -> TriageEngine:
    """Provides a TriageEngine configured with the populated test registry."""
    risk_eng = RiskEngine(registry=populated_registry)
    return TriageEngine(
        risk_engine=risk_eng,
        registry=populated_registry,
        containment_threshold=75.0,
        review_threshold=45.0,
    )


def test_triage_critical_containment_high_risk_score(triage_engine: TriageEngine):
    """Verify high-severity alert crossing score 75.0 triggers CRITICAL_CONTAINMENT."""
    # CRITICAL base (85) + Admin VIP target (15) = 100.0 (clamped)
    alert = make_alert(
        severity="CRITICAL",
        source_ip="203.0.113.88",
        target_users=["secops_admin"],
        mitre_technique="T1078.002",
        event_count=10,
    )

    assessment = triage_engine.triage(alert)
    assert assessment.verdict == TriageVerdict.CRITICAL_CONTAINMENT
    assert assessment.requires_containment is True
    assert assessment.risk_score >= 75.0
    assert any("Contain source IP 203.0.113.88" in action for action in assessment.recommended_actions)
    assert any("credential revocation" in action for action in assessment.recommended_actions)


def test_triage_crown_jewel_threshold_escalation(triage_engine: TriageEngine):
    """Verify crown jewel targeting escalates alerts scoring >= 60.0 to CRITICAL_CONTAINMENT."""
    # MEDIUM base (40) + Crown Jewel (20) = 60.0
    alert = make_alert(
        severity="MEDIUM",
        source_ip="192.168.10.40",
        target_hostname="core-vault01.corp",
        target_users=["regular_user"],
        mitre_technique="T1110.001",
    )

    assessment = triage_engine.triage(alert)
    assert assessment.risk_score == 60.0
    assert assessment.verdict == TriageVerdict.CRITICAL_CONTAINMENT
    assert assessment.requires_containment is True
    assert any("network micro-segmentation / isolation" in action for action in assessment.recommended_actions)


def test_triage_suspicious_review_verdict(triage_engine: TriageEngine):
    """Verify alerts with scores in range [45.0, 75.0) on non-crown jewels route to SUSPICIOUS_REVIEW."""
    # HIGH base (65) on standard asset = 65.0
    alert = make_alert(
        severity="HIGH",
        source_ip="198.51.100.12",
        target_hostname="web-front01.corp",
        target_users=["regular_user"],
        mitre_technique="T1110.003",
    )

    assessment = triage_engine.triage(alert)
    # 65.0 is >= review_threshold (45.0) and < containment_threshold (75.0)
    assert assessment.verdict == TriageVerdict.SUSPICIOUS_REVIEW
    assert assessment.requires_containment is False
    assert any("Correlate source IP" in action for action in assessment.recommended_actions)
    assert any("out-of-band channel" in action for action in assessment.recommended_actions)


def test_triage_benign_noise_verdict(triage_engine: TriageEngine):
    """Verify alerts scoring below review threshold (< 45.0) route to BENIGN_NOISE."""
    # LOW base (20) + standard asset = 20.0
    alert = make_alert(
        severity="LOW",
        source_ip="10.0.0.15",
        target_hostname="web-front01.corp",
        target_users=["regular_user"],
        mitre_technique="T1110",
    )

    assessment = triage_engine.triage(alert)
    assert assessment.risk_score < 45.0
    assert assessment.verdict == TriageVerdict.BENIGN_NOISE
    assert assessment.requires_containment is False
    assert any("archive alert" in action for action in assessment.recommended_actions)


def test_triage_false_positive_metadata_override(triage_engine: TriageEngine):
    """Verify authorized scans or whitelisted indicators force FALSE_POSITIVE verdict."""
    alert = make_alert(
        severity="CRITICAL",  # High base severity
        source_ip="10.50.1.200",
        target_hostname="core-vault01.corp",
        target_users=["secops_admin"],
        metadata={"is_authorized_scan": True},
    )

    assessment = triage_engine.triage(alert)
    assert assessment.verdict == TriageVerdict.FALSE_POSITIVE
    assert assessment.requires_containment is False
    assert any("Alert suppressed: verified authorized scan" in factor for factor in assessment.risk_factors)
    assert any("Verify scan authorization ticket" in action for action in assessment.recommended_actions)


def test_mitre_tactics_resolution_and_fallback(triage_engine: TriageEngine):
    """Verify technique to tactic mapping handles specific IDs and unknown sub-techniques."""
    # Explicit mapping: T1110.003 -> Credential Access
    alert_spray = make_alert(mitre_technique="T1110.003")
    assess_spray = triage_engine.triage(alert_spray)
    assert assess_spray.mitre_tactics == ["Credential Access"]

    # Explicit mapping: T1078.004 -> Defense Evasion, Persistence, Privilege Escalation
    alert_priv = make_alert(mitre_technique="T1078.004")
    assess_priv = triage_engine.triage(alert_priv)
    assert "Persistence" in assess_priv.mitre_tactics
    assert "Privilege Escalation" in assess_priv.mitre_tactics

    # Sub-technique fallback: T1110.999 splits to T1110
    alert_sub = make_alert(mitre_technique="T1110.999")
    assess_sub = triage_engine.triage(alert_sub)
    assert assess_sub.mitre_tactics == ["Credential Access"]


def test_triage_batch_sorting(triage_engine: TriageEngine):
    """Verify triage_batch sorts results descending by computed risk score."""
    alert_low = make_alert(severity="LOW", target_users=["regular_user"])
    alert_high = make_alert(severity="HIGH", target_users=["regular_user"])
    alert_crit = make_alert(severity="CRITICAL", target_users=["secops_admin"])

    # Pass in unsorted order
    batch = [alert_low, alert_crit, alert_high]
    assessments = triage_engine.triage_batch(batch)

    assert len(assessments) == 3
    assert assessments[0].risk_score >= assessments[1].risk_score >= assessments[2].risk_score
    assert assessments[0].verdict == TriageVerdict.CRITICAL_CONTAINMENT
    assert assessments[-1].verdict == TriageVerdict.BENIGN_NOISE
    