from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from src.models import EventType, SecurityAlert, UnifiedAuthRecord


class PasswordSprayRule:
    """Detects horizontal password spraying across multiple distinct accounts from a single source."""

    def __init__(
        self,
        rule_id: str = "RULE-PW-SPRAY-001",
        rule_name: str = "Password Spraying Detection",
        mitre_technique: str = "T1110.003",
        severity: str = "HIGH",
        user_threshold: int = 5,
        window_seconds: int = 300,
        alert_cooldown_seconds: int = 300,
    ) -> None:
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.mitre_technique = mitre_technique
        self.severity = severity
        self.user_threshold = user_threshold
        self.window_seconds = window_seconds
        self.alert_cooldown_seconds = alert_cooldown_seconds

        # Map of source_ip -> list of (timestamp_epoch, username)
        self._history: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        # Map of source_ip -> last_alert_timestamp_epoch
        self._last_alert_time: Dict[str, float] = {}

    def _to_epoch(self, dt: datetime) -> float:
        """Converts datetime to UTC epoch seconds."""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc).timestamp()
        return dt.astimezone(timezone.utc).timestamp()

    def evaluate(self, event: UnifiedAuthRecord) -> Optional[SecurityAlert]:
        """Evaluates an incoming UnifiedAuthRecord and emits a SecurityAlert if threshold is crossed."""
        if event.event_type not in (EventType.FAILED_LOGIN, EventType.INVALID_USER):
            return None

        src_ip = str(event.source_ip)
        current_time = self._to_epoch(event.timestamp)
        cutoff_time = current_time - self.window_seconds

        # 1. Slide window: prune entries older than window_seconds
        valid_entries = [
            (ts, user) for ts, user in self._history[src_ip] if ts >= cutoff_time
        ]
        valid_entries.append((current_time, event.username.strip().lower()))
        self._history[src_ip] = valid_entries

        # 2. Extract distinct targeted accounts
        unique_targets: Set[str] = {user for _, user in valid_entries}

        if len(unique_targets) < self.user_threshold:
            return None

        # 3. Check alert cooldown to prevent alert flooding
        last_alert = self._last_alert_time.get(src_ip, 0.0)
        if (current_time - last_alert) < self.alert_cooldown_seconds:
            return None

        # 4. Trigger alert
        self._last_alert_time[src_ip] = current_time
        timestamps = [ts for ts, _ in valid_entries]
        first_seen_epoch = min(timestamps)
        last_seen_epoch = max(timestamps)

        return SecurityAlert(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            mitre_technique=self.mitre_technique,
            severity=self.severity,
            source_ip=src_ip,
            target_users=sorted(list(unique_targets)),
            event_count=len(valid_entries),
            first_seen=datetime.fromtimestamp(first_seen_epoch, tz=timezone.utc),
            last_seen=datetime.fromtimestamp(last_seen_epoch, tz=timezone.utc),
            metadata={
                "distinct_targets_count": len(unique_targets),
                "window_seconds": self.window_seconds,
                "attack_vector": "horizontal_credential_spray",
            },
        )

    def process_batch(self, events: List[UnifiedAuthRecord]) -> List[SecurityAlert]:
        """Processes a sequence of records chronologically and returns triggered alerts."""
        alerts: List[SecurityAlert] = []
        sorted_events = sorted(events, key=lambda e: self._to_epoch(e.timestamp))
        for event in sorted_events:
            alert = self.evaluate(event)
            if alert:
                alerts.append(alert)
        return alerts

    def reset(self) -> None:
        """Clears in-memory history and alert states."""
        self._history.clear()
        self._last_alert_time.clear()
        