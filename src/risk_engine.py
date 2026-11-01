from typing import Any, Dict, List, Optional, Tuple

from src.asset_registry import AssetIdentityRegistry
from src.models import (
    AssetContext,
    CriticalityLevel,
    SecurityAlert,
    UserContext,
    UserRole,
)


class RiskEngine:
    """Calculates multi-factor composite risk scores (0.0 - 100.0) for security alerts."""

    BASE_SEVERITY_WEIGHTS: Dict[str, float] = {
        "LOW": 20.0,
        "MEDIUM": 40.0,
        "HIGH": 65.0,
        "CRITICAL": 85.0,
    }

    def __init__(self, registry: Optional[AssetIdentityRegistry] = None) -> None:
        self.registry = registry or AssetIdentityRegistry()

    def evaluate(
        self,
        alert: SecurityAlert,
        asset_context: Optional[AssetContext] = None,
        user_context: Optional[UserContext] = None,
        threat_intel_score: float = 0.0,
        is_known_malicious: bool = False,
    ) -> Tuple[float, List[str], AssetContext, Optional[UserContext]]:
        """Calculates a composite risk score and produces an itemized risk factor audit trail.

        Returns:
            Tuple of (final_risk_score, risk_factors, resolved_asset, resolved_user)
        """
        risk_factors: List[str] = []

        # 1. Base Severity Contribution
        severity_key = alert.severity.upper()
        base_score = self.BASE_SEVERITY_WEIGHTS.get(severity_key, 30.0)
        current_score = base_score
        risk_factors.append(f"Base severity '{severity_key}' (+{base_score:.1f})")

        # 2. Asset Criticality Resolution
        target_hostname = alert.metadata.get("target_hostname") or alert.source_ip
        asset = asset_context or self.registry.get_asset(str(target_hostname))

        if asset.is_crown_jewel:
            current_score += 20.0
            risk_factors.append(f"Target asset '{asset.hostname}' is CROWN JEWEL (+20.0)")
        elif asset.criticality == CriticalityLevel.MISSION_CRITICAL:
            current_score += 15.0
            risk_factors.append(f"Target asset '{asset.hostname}' is MISSION_CRITICAL (+15.0)")
        elif asset.criticality == CriticalityLevel.HIGH:
            current_score += 10.0
            risk_factors.append(f"Target asset '{asset.hostname}' has HIGH criticality (+10.0)")
        elif asset.criticality == CriticalityLevel.MEDIUM:
            current_score += 5.0
            risk_factors.append(f"Target asset '{asset.hostname}' has MEDIUM criticality (+5.0)")

        # 3. Targeted Identity Context & Privilege Level
        resolved_user: Optional[UserContext] = user_context
        if alert.target_users:
            primary_username = alert.target_users[0]
            if not resolved_user:
                resolved_user = self.registry.get_user(primary_username)

            if resolved_user.role in (UserRole.PRIVILEGED_ADMIN, UserRole.EXECUTIVE_VIP) or resolved_user.is_vip:
                current_score += 15.0
                risk_factors.append(
                    f"Target user '{resolved_user.username}' holds privileged/VIP role '{resolved_user.role.value}' (+15.0)"
                )
            elif resolved_user.role == UserRole.SERVICE_ACCOUNT:
                current_score += 10.0
                risk_factors.append(
                    f"Target user '{resolved_user.username}' is a SERVICE_ACCOUNT (+10.0)"
                )

        # 4. Attack Volume & Temporal Velocity
        if alert.event_count >= 50:
            current_score += 15.0
            risk_factors.append(f"Extreme event volume ({alert.event_count} events) (+15.0)")
        elif alert.event_count >= 20:
            current_score += 10.0
            risk_factors.append(f"High event volume ({alert.event_count} events) (+10.0)")
        elif alert.event_count >= 5:
            current_score += 5.0
            risk_factors.append(f"Repeated event volume ({alert.event_count} events) (+5.0)")

        # Burst velocity: >= 10 attempts compressed into <= 60 seconds
        time_span = (alert.last_seen - alert.first_seen).total_seconds()
        if time_span <= 60.0 and alert.event_count >= 10:
            current_score += 5.0
            risk_factors.append(f"High-velocity burst attack ({time_span:.1f}s window) (+5.0)")

        # 5. External Threat Intelligence & Reputation
        meta_ti_malicious = alert.metadata.get("is_known_malicious", False)
        meta_is_tor = alert.metadata.get("is_tor", False)

        if is_known_malicious or meta_ti_malicious:
            current_score += 20.0
            risk_factors.append(f"Source IP '{alert.source_ip}' identified as active threat actor (+20.0)")
        elif meta_is_tor:
            current_score += 15.0
            risk_factors.append(f"Source IP '{alert.source_ip}' is a verified Tor exit node (+15.0)")

        if threat_intel_score > 0.0:
            ti_boost = min(15.0, (threat_intel_score / 100.0) * 15.0)
            current_score += ti_boost
            risk_factors.append(f"Threat intelligence reputation score {threat_intel_score:.1f} (+{ti_boost:.1f})")

        # Clamp between 0.0 and 100.0
        final_score = round(max(0.0, min(100.0, current_score)), 2)

        return final_score, risk_factors, asset, resolved_user
        