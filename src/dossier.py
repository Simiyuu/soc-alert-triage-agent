from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field

from src.containment import ContainmentPlan
from src.models import (
    AssetContext,
    SecurityAlert,
    TriageAssessment,
    TriageVerdict,
    UserContext,
)


class IncidentDossier(BaseModel):
    """Complete incident package containing alert telemetry, triage assessment, and containment actions."""

    dossier_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    assessment: TriageAssessment
    alert: SecurityAlert
    containment_plan: Optional[ContainmentPlan] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the incident dossier into a dictionary."""
        return json.loads(self.model_dump_json())

    def to_json(self, indent: int = 2) -> str:
        """Serializes the incident dossier into formatted JSON."""
        return self.model_dump_json(indent=indent)

    def to_markdown(self) -> str:
        """Generates a comprehensive, human-readable SOC Incident Dossier in Markdown format."""
        verdict_str = self.assessment.verdict.value
        risk_score = self.assessment.risk_score
        tactics_str = ", ".join(self.assessment.mitre_tactics) or "Unassigned"
        techniques_str = ", ".join(self.assessment.mitre_techniques) or self.alert.mitre_technique

        # Asset & User representation
        asset: Optional[AssetContext] = self.assessment.asset_context
        user: Optional[UserContext] = self.assessment.user_context

        asset_name = asset.hostname if asset else "Uncataloged"
        asset_crit = asset.criticality.value if asset else "LOW"
        is_cj_str = "YES (CRITICAL)" if (asset and asset.is_crown_jewel) else "No"
        target_user = user.username if user else (self.alert.target_users[0] if self.alert.target_users else "None")
        user_role = user.role.value if user else "STANDARD"
        user_dept = user.department if user else "General"

        lines: List[str] = [
            f"# SOC INCIDENT DOSSIER: {self.alert.rule_name}",
            "",
            f"**Dossier ID:** `{self.dossier_id}`  ",
            f"**Alert ID:** `{self.alert.alert_id}`  ",
            f"**Assessment Timestamp:** `{self.assessment.timestamp.isoformat()}`  ",
            "",
            "## 1. Executive Summary & Triage Verdict",
            "",
            f"- **Triage Verdict:** `{verdict_str}`",
            f"- **Composite Risk Score:** **{risk_score:.1f} / 100.0**",
            f"- **Containment Required:** {'**YES**' if self.assessment.requires_containment else 'No'}",
            f"- **Base Severity:** `{self.alert.severity}`",
            f"- **MITRE ATT&CK Tactics:** {tactics_str}",
            f"- **MITRE ATT&CK Techniques:** `{techniques_str}`",
            "",
            "## 2. Target Context & Environmental Impact",
            "",
            "| Entity | Details | Criticality / Privileges |",
            "| :--- | :--- | :--- |",
            f"| **Target Host** | `{asset_name}` | Criticality: `{asset_crit}` (Crown Jewel: {is_cj_str}) |",
            f"| **Target Identity** | `{target_user}` | Role: `{user_role}` (Dept: {user_dept}) |",
            f"| **Attacker Origin** | `{self.alert.source_ip}` | Event Count: `{self.alert.event_count}` |",
            "",
            "## 3. Threat Telemetry & Risk Factors",
            "",
            f"- **First Observed:** `{self.alert.first_seen.isoformat()}`",
            f"- **Last Observed:** `{self.alert.last_seen.isoformat()}`",
            f"- **Observed Accounts:** {', '.join(f'`{u}`' for u in self.alert.target_users)}",
            "",
            "**Contributing Risk Vectors:**",
        ]

        for factor in self.assessment.risk_factors:
            lines.append(f"- {factor}")

        # Containment Section
        if self.containment_plan and self.containment_plan.requires_containment:
            lines.extend([
                "",
                "## 4. Automated Containment Playbook",
                "",
            ])

            if self.containment_plan.firewall_commands:
                lines.extend([
                    "### Perimeter & Host Firewall Blocks",
                    "```bash",
                    *self.containment_plan.firewall_commands,
                    "```",
                    "",
                ])

            if self.containment_plan.identity_actions:
                lines.extend([
                    "### Identity Revocation & Account Lockout",
                    "```powershell",
                    *self.containment_plan.identity_actions,
                    "```",
                    "",
                ])

            if self.containment_plan.host_isolation_commands:
                lines.extend([
                    "### Host Network Micro-Segmentation / Isolation",
                    "```bash",
                    *self.containment_plan.host_isolation_commands,
                    "```",
                    "",
                ])
        else:
            lines.extend([
                "",
                "## 4. Automated Containment Playbook",
                "",
                "_No automated containment required for this verdict._",
                "",
            ])

        # Recommended Actions
        lines.extend([
            "## 5. Analyst Remediation Runbook",
            "",
        ])
        for idx, action in enumerate(self.assessment.recommended_actions, 1):
            lines.append(f"{idx}. {action}")

        lines.append("")
        return "\n".join(lines)


class IncidentDossierGenerator:
    """Generates structured incident dossiers and SOC runbooks from triage results."""

    def generate(
        self,
        assessment: TriageAssessment,
        alert: SecurityAlert,
        containment_plan: Optional[ContainmentPlan] = None,
    ) -> IncidentDossier:
        """Assembles a complete IncidentDossier ready for reporting and export."""
        return IncidentDossier(
            assessment=assessment,
            alert=alert,
            containment_plan=containment_plan,
        )
    