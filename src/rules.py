from datetime import datetime
from typing import List, Optional
from src.models import EventType, SecurityAlert, UnifiedAuthRecord
from src.state_engine import SlidingWindowStateTracker


class VerticalBruteForceRule:
    """Detects repeated authentication failures targeting a single account from one source IP (MITRE T1110.001)."""

    def __init__(self, failure_threshold: int = 5, window_seconds: int = 60):
        self.threshold = failure_threshold
        self.tracker = SlidingWindowStateTracker(window_seconds=window_seconds)

    def evaluate(self, event: UnifiedAuthRecord) -> Optional[SecurityAlert]:
        if event.event_type not in (EventType.FAILED_LOGIN, EventType.INVALID_USER):
            return None

        # Keyed on both source IP and target username
        key = f"{event.source_ip}:{event.username}"
        self.tracker.add_event(key=key, event=event)

        active_events = self.tracker.get_events(key=key, current_time=event.timestamp)
        if len(active_events) == self.threshold:
            sorted_events = sorted(active_events, key=lambda e: e.timestamp)
            return SecurityAlert(
                rule_id="SOC-RULE-001",
                rule_name="Vertical Brute Force",
                mitre_technique="T1110.001",
                severity="HIGH",
                source_ip=str(event.source_ip),
                target_users=[event.username],
                event_count=len(active_events),
                first_seen=sorted_events[0].timestamp,
                last_seen=sorted_events[-1].timestamp,
                metadata={"service": event.service, "hostname": event.hostname},
            )
        return None


class HorizontalPasswordSprayRule:
    """Detects a single source IP probing many distinct accounts (MITRE T1110.003)."""

    def __init__(self, distinct_user_threshold: int = 5, window_seconds: int = 300):
        self.threshold = distinct_user_threshold
        self.tracker = SlidingWindowStateTracker(window_seconds=window_seconds)

    def evaluate(self, event: UnifiedAuthRecord) -> Optional[SecurityAlert]:
        if event.event_type not in (EventType.FAILED_LOGIN, EventType.INVALID_USER):
            return None

        # Keyed strictly by source IP
        key = str(event.source_ip)
        self.tracker.add_event(key=key, event=event)

        distinct_users = self.tracker.get_distinct_field_values(
            key=key, field_name="username", current_time=event.timestamp
        )

        if len(distinct_users) == self.threshold:
            active_events = self.tracker.get_events(key=key, current_time=event.timestamp)
            sorted_events = sorted(active_events, key=lambda e: e.timestamp)
            return SecurityAlert(
                rule_id="SOC-RULE-002",
                rule_name="Horizontal Password Spray",
                mitre_technique="T1110.003",
                severity="CRITICAL",
                source_ip=str(event.source_ip),
                target_users=list(distinct_users),
                event_count=len(active_events),
                first_seen=sorted_events[0].timestamp,
                last_seen=sorted_events[-1].timestamp,
                metadata={"service": event.service, "hostname": event.hostname},
            )
        return None
    