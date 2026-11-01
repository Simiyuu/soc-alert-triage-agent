from typing import List, Optional
from pydantic import BaseModel, Field

from src.models import (
    CriticalityLevel,
    SecurityAlert,
    TriageAssessment,
    TriageVerdict,
)


class ContainmentPlan(BaseModel):
    """Encapsulates executable system, network, and identity containment actions."""

    assessment_id: str
    verdict: TriageVerdict
    requires_containment: bool
    target_source_ip: Optional[str] = None
    target_username: Optional[str] = None
    target_hostname: Optional[str] = None
    firewall_commands: List[str] = Field(default_factory=list)
    identity_actions: List[str] = Field(default_factory=list)
    host_isolation_commands: List[str] = Field(default_factory=list)
    remediation_summary: List[str] = Field(default_factory=list)


class ContainmentEngine:
    """Compiles multi-platform containment playbooks for triage assessments requiring mitigation."""

    def __init__(self, management_cidr: str = "10.50.0.0/24") -> None:
        self.management_cidr = management_cidr

    def generate_plan(
        self,
        assessment: TriageAssessment,
        alert: Optional[SecurityAlert] = None,
        source_ip: Optional[str] = None,
    ) -> ContainmentPlan:
        """Translates an assessment into a concrete, executable containment plan."""
        # Resolve target source IP from argument, alert, or asset context
        resolved_ip = source_ip
        if not resolved_ip and alert:
            resolved_ip = alert.source_ip
        if not resolved_ip and assessment.asset_context and assessment.asset_context.ip_address:
            resolved_ip = assessment.asset_context.ip_address

        # Resolve target username
        resolved_username: Optional[str] = None
        if assessment.user_context:
            resolved_username = assessment.user_context.username
        elif alert and alert.target_users:
            resolved_username = alert.target_users[0]

        # Resolve target hostname
        resolved_hostname: Optional[str] = None
        if assessment.asset_context:
            resolved_hostname = assessment.asset_context.hostname

        # If containment is not warranted, return an inactive plan
        if not assessment.requires_containment:
            return ContainmentPlan(
                assessment_id=assessment.assessment_id,
                verdict=assessment.verdict,
                requires_containment=False,
                target_source_ip=resolved_ip,
                target_username=resolved_username,
                target_hostname=resolved_hostname,
                remediation_summary=[
                    f"No containment required for verdict: {assessment.verdict.value} (Risk Score: {assessment.risk_score:.1f})"
                ],
            )

        firewall_cmds: List[str] = []
        identity_cmds: List[str] = []
        isolation_cmds: List[str] = []
        summary: List[str] = []

        # 1. Perimeter and Host-Level Firewall Blocking (Target Source IP)
        if resolved_ip and resolved_ip != "unknown":
            firewall_cmds.extend([
                f"# Linux iptables drop rule",
                f"iptables -I INPUT -s {resolved_ip} -j DROP",
                f"# Linux nftables rule",
                f"nft add rule inet filter input ip saddr {resolved_ip} counter drop",
                f"# Windows Advanced Firewall (PowerShell)",
                f'New-NetFirewallRule -DisplayName "SOC-Containment-Block-{resolved_ip}" -Direction Inbound -Action Block -RemoteAddress {resolved_ip}',
                f"# Windows Netsh fallback",
                f'netsh advfirewall firewall add rule name="SOC-Block-{resolved_ip}" dir=in action=block remoteip={resolved_ip}',
            ])
            summary.append(f"Perimeter/host firewall block generated for attacker IP: {resolved_ip}")

        # 2. Targeted Identity Containment & Credential Lockout
        if resolved_username and resolved_username.lower() not in ("unknown", "anonymous"):
            identity_cmds.extend([
                f"# Active Directory Account Lockout (PowerShell)",
                f'Disable-ADAccount -Identity "{resolved_username}"',
                f"# Invalidate Active Directory / Entra ID Sessions",
                f'Revoke-AzureADUserAllRefreshToken -ObjectId "{resolved_username}"',
                f"# Linux Local User Lockout",
                f"passwd -l {resolved_username}",
                f"pkill -KILL -u {resolved_username}",
            ])
            summary.append(f"Active Directory and local credential lockout compiled for: {resolved_username}")

        # 3. Host Network Micro-Segmentation / Isolation
        asset = assessment.asset_context
        if asset and (asset.is_crown_jewel or asset.criticality in (CriticalityLevel.HIGH, CriticalityLevel.MISSION_CRITICAL)):
            isolation_cmds.extend([
                f"# Emergency host isolation on {resolved_hostname} (preserves SecOps management subnet {self.management_cidr})",
                f"iptables -P INPUT DROP",
                f"iptables -P FORWARD DROP",
                f"iptables -P OUTPUT DROP",
                f"iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                f"iptables -A INPUT -s {self.management_cidr} -p tcp --dport 22 -j ACCEPT",
                f"iptables -A OUTPUT -d {self.management_cidr} -p tcp --sport 22 -j ACCEPT",
                f'# Windows Host Isolation (PowerShell)',
                f'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True',
                f'New-NetFirewallRule -DisplayName "SOC-Emergency-Isolation" -Direction Inbound -Action Block',
            ])
            summary.append(f"Network micro-segmentation / host isolation generated for: {resolved_hostname}")

        return ContainmentPlan(
            assessment_id=assessment.assessment_id,
            verdict=assessment.verdict,
            requires_containment=True,
            target_source_ip=resolved_ip,
            target_username=resolved_username,
            target_hostname=resolved_hostname,
            firewall_commands=firewall_cmds,
            identity_actions=identity_cmds,
            host_isolation_commands=isolation_cmds,
            remediation_summary=summary,
        )

    