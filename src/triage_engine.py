from typing import Dict, List, Optional

from src.asset_registry import AssetIdentityRegistry
from src.models import (
    AssetContext,
    SecurityAlert,
    TriageAssessment,
    TriageVerdict,
    UserContext,
)
from src.risk_engine import RiskEngine


class TriageEngine:
    """Evaluates security alerts and risk factors to produce structured operational triage assessments."""

    MITRE_TACTIC_MAP: Dict[str, List[str]] = {
        "T1110": ["Credential Access"],
        "T1110.001": ["Credential Access"],
        "T1110.003": ["Credential Access"],
        "T1078": ["Defense Evasion", "Initial Access", "Persistence", "Privilege Escalation"],
        "T1078.001": ["Defense Evasion", "Initial Access", "Persistence", "Privilege Escalation"],
        "T1078.002": ["Defense Evasion", "Initial Access", "Persistence", "Privilege Escalation"],
        "T1078.004": ["Defense Evasion", "Persistence", "Privilege Escalation"],
    }

    def __init__(
        self,
        risk_engine: Optional[RiskEngine] = None,
        registry: Optional[AssetIdentityRegistry] = None,
        containment_threshold: float = 75.0,
        review_threshold: float = 45.0,
    ) -> None:
        self.registry = registry or AssetIdentityRegistry()
        self.risk_engine = risk_engine or RiskEngine(registry=self.registry)
        self.containment_threshold = containment_threshold
        self.review_threshold = review_threshold

    def _resolve_tactics(self, technique_id: str) -> List[str]:
        """Resolves MITRE tactics associated with a technique ID."""
        tech_clean = technique_id.strip()
        if tech_clean in self.MITRE_TACTIC_MAP:
            return self.MITRE_TACTIC_MAP[tech_clean]

        # Fallback to parent technique if sub-technique is unlisted
        parent = tech_clean.split(".")[0]
        return self.MITRE_TACTIC_MAP.get(parent, ["Credential Access"])

    def _generate_recommendations(
        self,
        verdict: TriageVerdict,
        alert: SecurityAlert,
        asset: AssetContext,
        user: Optional[UserContext],
        requires_containment: bool,
    ) -> List[str]:
        """Generates prescriptive SOC analyst action items based on triage outcome."""
        actions: List[str] = []
        target_name = user.username if user else "affected accounts"

        if verdict == TriageVerdict.CRITICAL_CONTAINMENT or requires_containment:
            actions.append(f"Contain source IP {alert.source_ip} via border firewall / perimeter ACL drop rules.")
            if asset.is_crown_jewel or asset.criticality.value in ("HIGH", "MISSION_CRITICAL"):
                actions.append(f"Initiate network micro-segmentation / isolation for host '{asset.hostname}'.")
            actions.append(f"Trigger emergency credential revocation and session invalidation for '{target_name}'.")
            actions.append("Capture volatile forensic artifacts (memory dump and active network socket tables).")
            actions.append("Escalate to Tier-3 Incident Response Lead.")

        elif verdict == TriageVerdict.SUSPICIOUS_REVIEW:
            actions.append(f"Correlate source IP {alert.source_ip} against VPN and proxy authentication logs.")
            actions.append(f"Contact target user '{target_name}' via out-of-band channel to verify login authenticity.")
            actions.append(f"Monitor asset '{asset.hostname}' for subsequent execution or lateral movement anomalies.")

        elif verdict == TriageVerdict.FALSE_POSITIVE:
            actions.append(f"Verify scan authorization ticket or change control window for {alert.source_ip}.")
            actions.append("Update detection suppression whitelist to eliminate recurring scanner noise.")

        else:  # BENIGN_NOISE
            actions.append("Log event and archive alert in telemetry repository.")
            actions.append("No active analyst remediation required.")

        return actions

    def triage(
        self,
        alert: SecurityAlert,
        threat_intel_score: float = 0.0,
        is_known_malicious: bool = False,
    ) -> TriageAssessment:
        """Executes full autonomous triage assessment for an incoming security alert."""
        # 1. Compute dynamic risk score and identify contributing factors
        risk_score, risk_factors, asset, user = self.risk_engine.evaluate(
            alert,
            threat_intel_score=threat_intel_score,
            is_known_malicious=is_known_malicious,
        )

        # 2. Check for explicit false-positive indicators in alert metadata
        is_authorized = alert.metadata.get("is_authorized_scan", False)
        is_whitelisted = alert.metadata.get("whitelisted", False)

        # 3. Determine operational verdict and containment necessity
        requires_containment = False

        if is_authorized or is_whitelisted:
            verdict = TriageVerdict.FALSE_POSITIVE
            risk_factors.append("Alert suppressed: verified authorized scan or whitelisted activity")
        elif risk_score >= self.containment_threshold or (asset.is_crown_jewel and risk_score >= 60.0):
            verdict = TriageVerdict.CRITICAL_CONTAINMENT
            requires_containment = True
        elif risk_score >= self.review_threshold:
            verdict = TriageVerdict.SUSPICIOUS_REVIEW
        else:
            verdict = TriageVerdict.BENIGN_NOISE

        # 4. Map MITRE ATT&CK tactics
        tactics = self._resolve_tactics(alert.mitre_technique)
        techniques = [alert.mitre_technique]

        # 5. Compile analyst recommendations
        recommendations = self._generate_recommendations(
            verdict=verdict,
            alert=alert,
            asset=asset,
            user=user,
            requires_containment=requires_containment,
        )

        return TriageAssessment(
            alert_id=alert.alert_id,
            risk_score=risk_score,
            verdict=verdict,
            risk_factors=risk_factors,
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            asset_context=asset,
            user_context=user,
            recommended_actions=recommendations,
            requires_containment=requires_containment,
        )

    def triage_batch(
        self,
        alerts: List[SecurityAlert],
        is_known_malicious: bool = False,
    ) -> List[TriageAssessment]:
        """Triages a batch of alerts and returns prioritised assessments."""
        assessments = [
            self.triage(alert, is_known_malicious=is_known_malicious)
            for alert in alerts
        ]
        # Sort descending by risk_score so highest priority incidents lead
        assessments.sort(key=lambda a: a.risk_score, reverse=True)
        return assessments
    