from datetime import datetime, timezone
import json
import uuid
import pytest

from src.containment import ContainmentEngine, ContainmentPlan
from src.dossier import IncidentDossier, IncidentDossierGenerator
from src.models import (
    AssetContext,
    CriticalityLevel,
    SecurityAlert,
    TriageAssessment,
    TriageVerdict,
    UserContext,
    UserRole,
)


@pytest.fixture
def sample_alert() -> SecurityAlert:
    """Fixture providing a standard security alert for dossier tests."""
    now = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
    return SecurityAlert(
        alert_id=str(uuid.uuid4()),
        timestamp=now,
        rule_id="RULE-SPRAY-001",
        rule_name="Password Spraying Detection",
        mitre_technique="T1110.003",
        severity="HIGH",
        source_ip="198.51.100.88",
        target_users=["alice", "bob", "charlie"],
        event_count=15,
        first_seen=now,
        last_seen=now,
        metadata={"attack_vector": "horizontal_credential_spray"},
    )


@pytest.fixture
def sample_assessment(sample_alert: SecurityAlert) -> TriageAssessment:
    """Fixture providing a critical triage assessment with asset and identity context."""
    now = datetime(2026, 11, 1, 12, 0, 5, tzinfo=timezone.utc)
    asset = AssetContext(
        hostname="core-auth-dc01.corp",
        ip_address="10.100.4.10",
        criticality=CriticalityLevel.MISSION_CRITICAL,
        business_unit="Core Infrastructure",
        is_crown_jewel=True,
    )
    user = UserContext(
        username="secops_lead",
        role=UserRole.PRIVILEGED_ADMIN,
        department="Security Operations",
        is_vip=True,
    )
    return TriageAssessment(
        alert_id=sample_alert.alert_id,
        timestamp=now,
        risk_score=92.5,
        verdict=TriageVerdict.CRITICAL_CONTAINMENT,
        risk_factors=[
            "Base severity 'HIGH' (+65.0)",
            "Target asset 'core-auth-dc01.corp' is CROWN JEWEL (+20.0)",
            "High event volume (15 events) (+5.0)",
        ],
        mitre_tactics=["Credential Access", "Lateral Movement"],
        mitre_techniques=["T1110.003"],
        asset_context=asset,
        user_context=user,
        recommended_actions=[
            "Contain source IP 198.51.100.88 via border firewall drop rules.",
            "Trigger emergency credential revocation for secops_lead.",
            "Escalate to Incident Response Lead.",
        ],
        requires_containment=True,
    )


@pytest.fixture
def sample_containment_plan(
    sample_assessment: TriageAssessment, sample_alert: SecurityAlert
) -> ContainmentPlan:
    """Fixture providing a compiled containment plan."""
    engine = ContainmentEngine(management_cidr="10.50.0.0/24")
    return engine.generate_plan(sample_assessment, alert=sample_alert)


def test_dossier_generator_builds_valid_dossier(
    sample_assessment: TriageAssessment,
    sample_alert: SecurityAlert,
    sample_containment_plan: ContainmentPlan,
):
    """Verify IncidentDossierGenerator aggregates components into an IncidentDossier."""
    generator = IncidentDossierGenerator()
    dossier = generator.generate(
        assessment=sample_assessment,
        alert=sample_alert,
        containment_plan=sample_containment_plan,
    )

    assert isinstance(dossier, IncidentDossier)
    assert dossier.assessment.alert_id == sample_alert.alert_id
    assert dossier.alert.rule_name == "Password Spraying Detection"
    assert dossier.containment_plan is not None
    assert dossier.containment_plan.requires_containment is True


def test_dossier_to_dict_and_to_json_serialization(
    sample_assessment: TriageAssessment,
    sample_alert: SecurityAlert,
    sample_containment_plan: ContainmentPlan,
):
    """Verify dictionary and JSON serialization preserves complete schema structure."""
    generator = IncidentDossierGenerator()
    dossier = generator.generate(sample_assessment, sample_alert, sample_containment_plan)

    # Dictionary serialization
    dossier_dict = dossier.to_dict()
    assert isinstance(dossier_dict, dict)
    assert dossier_dict["assessment"]["risk_score"] == 92.5
    assert dossier_dict["alert"]["source_ip"] == "198.51.100.88"
    assert dossier_dict["containment_plan"]["requires_containment"] is True

    # JSON serialization
    json_str = dossier.to_json()
    assert isinstance(json_str, str)
    parsed = json.loads(json_str)
    assert parsed["assessment"]["verdict"] == "CRITICAL_CONTAINMENT"
    assert "core-auth-dc01.corp" in json_str


def test_dossier_to_markdown_with_active_containment(
    sample_assessment: TriageAssessment,
    sample_alert: SecurityAlert,
    sample_containment_plan: ContainmentPlan,
):
    """Verify Markdown report formats executive sections and command code fences."""
    generator = IncidentDossierGenerator()
    dossier = generator.generate(sample_assessment, sample_alert, sample_containment_plan)
    md = dossier.to_markdown()

    # Core headers
    assert "# SOC INCIDENT DOSSIER: Password Spraying Detection" in md
    assert "## 1. Executive Summary & Triage Verdict" in md
    assert "## 2. Target Context & Environmental Impact" in md
    assert "## 3. Threat Telemetry & Risk Factors" in md
    assert "## 4. Automated Containment Playbook" in md
    assert "## 5. Analyst Remediation Runbook" in md

    # Executive details
    assert "**92.5 / 100.0**" in md
    assert "`CRITICAL_CONTAINMENT`" in md
    assert "Crown Jewel: YES (CRITICAL)" in md

    # Code blocks for containment
    assert "```bash" in md
    assert "iptables -I INPUT -s 198.51.100.88 -j DROP" in md
    assert "```powershell" in md
    assert 'Disable-ADAccount -Identity "secops_lead"' in md

    # Remediation checklist
    assert "1. Contain source IP 198.51.100.88" in md


def test_dossier_to_markdown_without_containment(
    sample_alert: SecurityAlert,
):
    """Verify Markdown report handles non-containment verdicts cleanly."""
    assessment = TriageAssessment(
        alert_id=sample_alert.alert_id,
        risk_score=35.0,
        verdict=TriageVerdict.BENIGN_NOISE,
        risk_factors=["Base severity 'LOW' (+20.0)"],
        mitre_tactics=["Credential Access"],
        mitre_techniques=["T1110.003"],
        recommended_actions=["Archive alert in telemetry log."],
        requires_containment=False,
    )
    plan = ContainmentPlan(
        assessment_id=assessment.assessment_id,
        verdict=TriageVerdict.BENIGN_NOISE,
        requires_containment=False,
        remediation_summary=["No containment required."],
    )

    generator = IncidentDossierGenerator()
    dossier = generator.generate(assessment, sample_alert, plan)
    md = dossier.to_markdown()

    assert "`BENIGN_NOISE`" in md
    assert "**35.0 / 100.0**" in md
    assert "_No automated containment required for this verdict._" in md
    assert "iptables" not in md
    assert "Disable-ADAccount" not in md


def test_dossier_to_markdown_handles_missing_context(sample_alert: SecurityAlert):
    """Verify Markdown generation falls back gracefully when asset and user contexts are None."""
    assessment = TriageAssessment(
        alert_id=sample_alert.alert_id,
        risk_score=50.0,
        verdict=TriageVerdict.SUSPICIOUS_REVIEW,
        risk_factors=["Uncataloged asset activity"],
        mitre_tactics=["Credential Access"],
        mitre_techniques=["T1110.003"],
        asset_context=None,
        user_context=None,
        recommended_actions=["Review target host manually."],
        requires_containment=False,
    )

    generator = IncidentDossierGenerator()
    dossier = generator.generate(assessment, sample_alert, None)
    md = dossier.to_markdown()

    assert "`Uncataloged`" in md
    assert "`STANDARD`" in md
    assert "1. Review target host manually." in md
    