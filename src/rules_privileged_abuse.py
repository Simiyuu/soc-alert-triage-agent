from datetime import datetime, timezone
from typing import List, Optional

from src.asset_registry import AssetIdentityRegistry
from src.models import (
    CriticalityLevel,
    EventType,
    SecurityAlert,
    UnifiedAuthRecord,
    UserRole,
)


class PrivilegedAccountAbuseRule:
    """Detects unauthorized, off-subnet, or off-hours logons by privileged identities and service accounts."""

    INTERACTIVE_LOGON_TYPES = {2, 10}  # Type 2: Interactive, Type 10: RemoteInteractive (RDP)

    def __init__(
        self,
        registry: Optional[AssetIdentityRegistry] = None,
        rule_id: str = "RULE-PRIV-ABUSE-001",
        rule_name: str = "Privileged Account Abuse Detection",
        mitre_technique: str = "T1078",
        business_hours_start: int = 6,  # 06:00 UTC
        business_hours_end: int = 20,   # 20:00 UTC
    ) -> None:
        self.registry = registry or AssetIdentityRegistry()
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.mitre_technique = mitre_technique
        self.business_hours_start = business_hours_start
        self.business_hours_end = business_hours_end

    def _is_off_hours(self, dt: datetime) -> bool:
        """Determines if a timestamp falls outside configured operational hours."""
        utc_dt = dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        hour = utc_dt.astimezone(timezone.utc).hour
        return hour < self.business_hours_start or hour >= self.business_hours_end

    def evaluate(self, event: UnifiedAuthRecord) -> Optional[SecurityAlert]:
        """Evaluates an authentication event against identity privileges, subnets, and asset context."""
        username = event.username.strip().lower()
        src_ip = str(event.source_ip).strip()
        user = self.registry.get_user(username)
        asset = self.registry.get_asset(event.hostname)

        # Heuristic fallback if user is uncataloged but matches service account naming convention
        is_service_account = (
            user.role == UserRole.SERVICE_ACCOUNT
            or username.startswith("svc_")
            or username.startswith("svc-")
        )
        is_privileged = (
            user.role in (UserRole.PRIVILEGED_ADMIN, UserRole.EXECUTIVE_VIP)
            or user.is_vip
            or username in ("administrator", "root")
        )

        violations: List[str] = []
        technique = self.mitre_technique

        # 1. Interactive Service Account Abuse (Logon Type 2/10 or SSH Interactive)
        if is_service_account:
            technique = "T1078.004"
            if event.logon_type in self.INTERACTIVE_LOGON_TYPES:
                violations.append(
                    f"Service account '{username}' executed interactive logon (Type {event.logon_type})"
                )
            elif event.service == "sshd" and event.event_type == EventType.ACCEPTED_LOGIN:
                violations.append(
                    f"Service account '{username}' established direct interactive SSH session"
                )

        # 2. Administrative Subnet Boundary Violation
        if (is_privileged or is_service_account) and not self.registry.is_approved_source(username, src_ip):
            violations.append(
                f"Privileged identity '{username}' authenticated from unapproved source IP {src_ip}"
            )
            technique = "T1078.002" if not is_service_account else "T1078.004"

        # 3. Off-Hours Access on High-Criticality / Crown-Jewel Assets
        if (is_privileged or is_service_account) and self._is_off_hours(event.timestamp):
            if asset.is_crown_jewel or asset.criticality in (CriticalityLevel.HIGH, CriticalityLevel.MISSION_CRITICAL):
                violations.append(
                    f"Off-hours access by '{username}' on critical asset '{asset.hostname}' at hour {event.timestamp.hour} UTC"
                )

        if not violations:
            return None

        # Severity escalation based on asset criticality and violation depth
        severity = "HIGH"
        if asset.is_crown_jewel or asset.criticality == CriticalityLevel.MISSION_CRITICAL or len(violations) >= 2:
            severity = "CRITICAL"

        now_utc = datetime.now(timezone.utc)
        event_time = event.timestamp if event.timestamp.tzinfo is not None else event.timestamp.replace(tzinfo=timezone.utc)

        return SecurityAlert(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            mitre_technique=technique,
            severity=severity,
            source_ip=src_ip,
            target_users=[username],
            event_count=1,
            first_seen=event_time,
            last_seen=event_time,
            metadata={
                "violations": violations,
                "user_role": user.role.value,
                "target_hostname": asset.hostname,
                "target_criticality": asset.criticality.value,
                "is_crown_jewel": asset.is_crown_jewel,
                "logon_type": event.logon_type,
            },
        )

    def process_batch(self, events: List[UnifiedAuthRecord]) -> List[SecurityAlert]:
        """Processes a sequence of records and returns alerts for all identified policy violations."""
        alerts: List[SecurityAlert] = []
        for event in events:
            alert = self.evaluate(event)
            if alert:
                alerts.append(alert)
        return alerts
    