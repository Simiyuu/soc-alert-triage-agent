import uuid
from pydantic import ValidationError
import pytest

from src.models import (
    AssetContext,
    CriticalityLevel,
    SecurityAlert,
    TriageAssessment,
    TriageVerdict,
    UserContext,
    UserRole,
)


def test_asset_context_defaults_and_customization():
    """Verify AssetContext initializes with secure defaults and accepts custom attributes."""
    default_asset = AssetContext(hostname="workstation-01")
    assert default_asset.hostname == "workstation-01"
    assert default_asset.criticality == CriticalityLevel.LOW
    assert default_asset.is_crown_jewel is False
    assert default_asset.environment == "production"

    crown_jewel = AssetContext(
        hostname="core-banking-db01",
        ip_address="10.100.4.50",
        criticality=CriticalityLevel.MISSION_CRITICAL,
        business_unit="Core Banking Operations",
        is_crown_jewel=True,
        environment="production",
    )
    assert crown_jewel.criticality == CriticalityLevel.MISSION_CRITICAL
    assert crown_jewel.is_crown_jewel is True
    assert crown_jewel.ip_address == "10.100.4.50"


def test_user_context_roles_and_subnets():
    """Verify UserContext models role assignments and approved subnet lists."""
    admin_user = UserContext(
        username="secops_admin",
        role=UserRole.PRIVILEGED_ADMIN,
        department="Information Security",
        is_vip=True,
        approved_source_subnets=["10.50.0.0/24", "192.168.10.0/24"],
    )
    assert admin_user.role == UserRole.PRIVILEGED_ADMIN
    assert admin_user.is_vip is True
    assert len(admin_user.approved_source_subnets) == 2


def test_triage_assessment_valid_instantiation():
    """Verify TriageAssessment constructs with valid risk scores and auto-generated UUIDs."""
    alert_id = str(uuid.uuid4())
    assessment = TriageAssessment(
        alert_id=alert_id,
        risk_score=85.5,
        verdict=TriageVerdict.CRITICAL_CONTAINMENT,
        risk_factors=["Brute force velocity exceeded", "Target is Crown Jewel DB"],
        mitre_tactics=["Credential Access", "Lateral Movement"],
        mitre_techniques=["T1110.001", "T1078"],
        requires_containment=True,
    )
    assert assessment.alert_id == alert_id
    assert assessment.risk_score == 85.5
    assert assessment.verdict == TriageVerdict.CRITICAL_CONTAINMENT
    assert assessment.requires_containment is True
    assert len(assessment.risk_factors) == 2


@pytest.mark.parametrize("invalid_score", [-0.1, -15.0, 100.1, 150.0])
def test_triage_assessment_score_bounds_validation(invalid_score):
    """Verify Pydantic enforces 0.0 <= risk_score <= 100.0 boundary checks."""
    with pytest.raises(ValidationError):
        TriageAssessment(
            alert_id=str(uuid.uuid4()),
            risk_score=invalid_score,
            verdict=TriageVerdict.SUSPICIOUS_REVIEW,
        )


def test_triage_verdict_enum_values():
    """Verify all four operational triage verdicts exist with expected values."""
    assert TriageVerdict.BENIGN_NOISE.value == "BENIGN_NOISE"
    assert TriageVerdict.FALSE_POSITIVE.value == "FALSE_POSITIVE"
    assert TriageVerdict.SUSPICIOUS_REVIEW.value == "SUSPICIOUS_REVIEW"
    assert TriageVerdict.CRITICAL_CONTAINMENT.value == "CRITICAL_CONTAINMENT"


def test_triage_assessment_composite_context_embedding():
    """Verify embedding full AssetContext and UserContext models inside TriageAssessment."""
    asset = AssetContext(
        hostname="ad-dc01.corp",
        criticality=CriticalityLevel.MISSION_CRITICAL,
        is_crown_jewel=True,
    )
    user = UserContext(
        username="administrator",
        role=UserRole.PRIVILEGED_ADMIN,
        is_vip=True,
    )
    assessment = TriageAssessment(
        alert_id=str(uuid.uuid4()),
        risk_score=95.0,
        verdict=TriageVerdict.CRITICAL_CONTAINMENT,
        asset_context=asset,
        user_context=user,
        recommended_actions=["Revoke Kerberos TGT", "Isolate DC network segment"],
        requires_containment=True,
    )

    assert assessment.asset_context is not None
    assert assessment.asset_context.hostname == "ad-dc01.corp"
    assert assessment.user_context is not None
    assert assessment.user_context.role == UserRole.PRIVILEGED_ADMIN
    