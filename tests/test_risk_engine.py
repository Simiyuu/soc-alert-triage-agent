from datetime import datetime, timedelta, timezone
from typing import List, Optional
import pytest

from src.asset_registry import AssetIdentityRegistry
from src.models import (
    AssetContext,
    CriticalityLevel,
    SecurityAlert,
    UserContext,
    UserRole,
)
from src.risk_engine import RiskEngine


def make_alert(
    severity: str = "MEDIUM",
    source_ip: str = "192.168.1.100",
    target_users: Optional[List[str]] = None,
    event_count: int = 1,
    time_span_seconds: float = 300.0,
    target_hostname: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> SecurityAlert:
    """Helper to construct standardized SecurityAlert instances for risk scoring tests."""
    now = datetime.now(timezone.utc)
    meta = metadata.copy() if metadata else {}
    if target_hostname:
        meta["target_hostname"] = target_hostname

    return SecurityAlert(
        rule_id="RULE-TEST-001",
        rule_name="Test Rule Execution",
        mitre_technique="T1110",
        severity=severity,
        source_ip=source_ip,
        target_users=target_users or ["regular_user"],
        event_count=event_count,
        first_seen=now - timedelta(seconds=time_span_seconds),
        last_seen=now,
        metadata=meta,
    )


@pytest.fixture
def populated_registry() -> AssetIdentityRegistry:
    """Provides an AssetIdentityRegistry populated with test assets and identities."""
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
            hostname="web-proxy01.corp",
            ip_address="172.16.1.10",
            criticality=CriticalityLevel.HIGH,
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
            username="svc_sql_sync",
            role=UserRole.SERVICE_ACCOUNT,
            is_vip=False,
        )
    )
    reg.register_user(
        UserContext(
            username="standard_user",
            role=UserRole.STANDARD,
            is_vip=False,
        )
    )

    return reg


@pytest.fixture
def risk_engine(populated_registry: AssetIdentityRegistry) -> RiskEngine:
    """Provides a RiskEngine wired to the populated registry."""
    return RiskEngine(registry=populated_registry)


def test_base_severity_scoring(risk_engine: RiskEngine):
    """Verify baseline severity values without external context modifiers."""
    low_alert = make_alert(severity="LOW", target_users=["standard_user"])
    score_low, factors_low, _, _ = risk_engine.evaluate(low_alert)
    assert score_low == 20.0
    assert any("Base severity 'LOW'" in f for f in factors_low)

    med_alert = make_alert(severity="MEDIUM", target_users=["standard_user"])
    score_med, factors_med, _, _ = risk_engine.evaluate(med_alert)
    assert score_med == 40.0

    high_alert = make_alert(severity="HIGH", target_users=["standard_user"])
    score_high, factors_high, _, _ = risk_engine.evaluate(high_alert)
    assert score_high == 65.0

    crit_alert = make_alert(severity="CRITICAL", target_users=["standard_user"])
    score_crit, factors_crit, _, _ = risk_engine.evaluate(crit_alert)
    assert score_crit == 85.0


def test_crown_jewel_and_criticality_boost(risk_engine: RiskEngine):
    """Verify crown jewel assets receive +20.0 boost and high criticality receives +10.0."""
    # Crown jewel asset targeted
    alert_cj = make_alert(
        severity="MEDIUM",
        target_hostname="core-vault01.corp",
        target_users=["standard_user"],
    )
    score_cj, factors_cj, asset_cj, _ = risk_engine.evaluate(alert_cj)
    # 40 (MEDIUM) + 20 (CROWN JEWEL) = 60.0
    assert score_cj == 60.0
    assert asset_cj.is_crown_jewel is True
    assert any("CROWN JEWEL (+20.0)" in f for f in factors_cj)

    # High criticality asset targeted
    alert_high_asset = make_alert(
        severity="MEDIUM",
        target_hostname="web-proxy01.corp",
        target_users=["standard_user"],
    )
    score_ha, factors_ha, asset_ha, _ = risk_engine.evaluate(alert_high_asset)
    # 40 (MEDIUM) + 10 (HIGH criticality) = 50.0
    assert score_ha == 50.0
    assert any("HIGH criticality (+10.0)" in f for f in factors_ha)


def test_privileged_user_and_service_account_boost(risk_engine: RiskEngine):
    """Verify admin/VIP accounts receive +15.0 and service accounts receive +10.0."""
    # Admin / VIP user targeted
    alert_admin = make_alert(
        severity="LOW",
        target_users=["secops_admin"],
    )
    score_admin, factors_admin, _, user_admin = risk_engine.evaluate(alert_admin)
    # 20 (LOW) + 15 (PRIVILEGED_ADMIN) = 35.0
    assert score_admin == 35.0
    assert user_admin is not None
    assert user_admin.role == UserRole.PRIVILEGED_ADMIN
    assert any("privileged/VIP role" in f for f in factors_admin)

    # Service account targeted
    alert_svc = make_alert(
        severity="LOW",
        target_users=["svc_sql_sync"],
    )
    score_svc, factors_svc, _, user_svc = risk_engine.evaluate(alert_svc)
    # 20 (LOW) + 10 (SERVICE_ACCOUNT) = 30.0
    assert score_svc == 30.0
    assert user_svc is not None
    assert user_svc.role == UserRole.SERVICE_ACCOUNT
    assert any("SERVICE_ACCOUNT (+10.0)" in f for f in factors_svc)


def test_volume_and_burst_velocity_multipliers(risk_engine: RiskEngine):
    """Verify event volume stacking and high-velocity burst detection."""
    # High volume (25 attempts across 120s)
    alert_vol = make_alert(
        severity="LOW",
        target_users=["standard_user"],
        event_count=25,
        time_span_seconds=120.0,
    )
    score_vol, factors_vol, _, _ = risk_engine.evaluate(alert_vol)
    # 20 (LOW) + 10 (High volume >= 20) = 30.0
    assert score_vol == 30.0
    assert any("High event volume (25 events) (+10.0)" in f for f in factors_vol)

    # High-velocity burst (15 attempts compressed into 30 seconds)
    alert_burst = make_alert(
        severity="LOW",
        target_users=["standard_user"],
        event_count=15,
        time_span_seconds=30.0,
    )
    score_burst, factors_burst, _, _ = risk_engine.evaluate(alert_burst)
    # 20 (LOW) + 5 (Repeated >= 5) + 5 (Burst <= 60s & >= 10 events) = 30.0
    assert score_burst == 30.0
    assert any("High-velocity burst attack" in f for f in factors_burst)


def test_threat_intel_and_tor_boosts(risk_engine: RiskEngine):
    """Verify threat intelligence flags and Tor exit node indicators increase risk score."""
    # Source is verified Tor node via metadata
    alert_tor = make_alert(
        severity="LOW",
        target_users=["standard_user"],
        metadata={"is_tor": True},
    )
    score_tor, factors_tor, _, _ = risk_engine.evaluate(alert_tor)
    # 20 (LOW) + 15 (Tor) = 35.0
    assert score_tor == 35.0
    assert any("verified Tor exit node (+15.0)" in f for f in factors_tor)

    # Source is verified active malicious threat actor
    alert_mal = make_alert(
        severity="LOW",
        target_users=["standard_user"],
    )
    score_mal, factors_mal, _, _ = risk_engine.evaluate(alert_mal, is_known_malicious=True)
    # 20 (LOW) + 20 (Malicious) = 40.0
    assert score_mal == 40.0
    assert any("identified as active threat actor (+20.0)" in f for f in factors_mal)

    # Continuous external threat intel reputation score (e.g., 80.0 / 100.0)
    score_ti, factors_ti, _, _ = risk_engine.evaluate(alert_mal, threat_intel_score=80.0)
    # 20 (LOW) + 12.0 (80% of 15.0) = 32.0
    assert score_ti == 32.0
    assert any("Threat intelligence reputation score 80.0 (+12.0)" in f for f in factors_ti)


def test_risk_score_clamping_at_100(risk_engine: RiskEngine):
    """Verify combined high-severity vectors are clamped strictly to 100.0 max."""
    # CRITICAL base (85) + Crown Jewel (20) + Admin VIP (15) + Extreme Volume (15) + Malicious (20) = 155
    alert_overload = make_alert(
        severity="CRITICAL",
        target_hostname="core-vault01.corp",
        target_users=["secops_admin"],
        event_count=100,
        time_span_seconds=20.0,
        metadata={"is_known_malicious": True},
    )
    score, factors, _, _ = risk_engine.evaluate(alert_overload, is_known_malicious=True)
    assert score == 100.0
    assert len(factors) >= 5


def test_registry_resolution_fallbacks(risk_engine: RiskEngine):
    """Verify RiskEngine safely resolves uncataloged endpoints and usernames without breaking."""
    alert_unknown = make_alert(
        severity="LOW",
        target_hostname="unregistered-laptop-123.corp",
        target_users=["contractor_temp"],
    )
    score, factors, asset, user = risk_engine.evaluate(alert_unknown)
    assert score == 20.0
    assert asset.hostname == "unregistered-laptop-123.corp"
    assert asset.criticality == CriticalityLevel.LOW
    assert user is not None
    assert user.username == "contractor_temp"
    assert user.role == UserRole.STANDARD
    