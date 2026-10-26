from datetime import datetime
from typing import Any, Dict, List, Optional
from src.geo_velocity import (
    GeoLocation,
    MockGeoIPDatabase,
    calculate_haversine_distance,
    calculate_travel_velocity,
    is_impossible_travel,
)
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

        key = f"{event.source_ip}:{event.username}"
        self.tracker.add_event(key=key, event=event)

        active_events = self.tracker.get_events(key=key, current_time=event.timestamp)
        if len(active_events) >= self.threshold:
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

        key = str(event.source_ip)
        self.tracker.add_event(key=key, event=event)

        distinct_users = self.tracker.get_distinct_field_values(
            key=key, field_name="username", current_time=event.timestamp
        )

        if len(distinct_users) >= self.threshold:
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


class ImpossibleTravelRule:
    """Correlates consecutive successful logins per user across physical geography

    to detect impossible travel velocities (MITRE T1078).
    """

    def __init__(self, speed_threshold_kmh: float = 800.0):
        self.threshold_kmh = speed_threshold_kmh
        self._user_locations: dict[str, tuple[GeoLocation, datetime]] = {}

    def evaluate(self, event: UnifiedAuthRecord) -> Optional[SecurityAlert]:
        if event.event_type != EventType.ACCEPTED_LOGIN:
            return None

        current_geo = MockGeoIPDatabase.lookup(str(event.source_ip))
        if current_geo.latitude is None or current_geo.longitude is None:
            return None

        username = event.username
        prev_entry = self._user_locations.get(username)

        self._user_locations[username] = (current_geo, event.timestamp)

        if prev_entry is None:
            return None

        prev_geo, prev_time = prev_entry
        velocity = calculate_travel_velocity(
            prev_geo, prev_time, current_geo, event.timestamp
        )

        if is_impossible_travel(velocity, threshold_kmh=self.threshold_kmh):
            distance = calculate_haversine_distance(
                prev_geo.latitude,
                prev_geo.longitude,
                current_geo.latitude,
                current_geo.longitude,
            )
            return SecurityAlert(
                rule_id="SOC-RULE-003",
                rule_name="Impossible Travel",
                mitre_technique="T1078",
                severity="CRITICAL",
                source_ip=str(event.source_ip),
                target_users=[username],
                event_count=2,
                first_seen=prev_time,
                last_seen=event.timestamp,
                metadata={
                    "origin_ip": prev_geo.ip,
                    "origin_city": prev_geo.city,
                    "origin_country": prev_geo.country,
                    "target_city": current_geo.city,
                    "target_country": current_geo.country,
                    "distance_km": round(distance, 2),
                    "velocity_kmh": round(velocity, 2) if velocity != float("inf") else "inf",
                },
            )

        return None


class DistributedBruteForceRule:
    """Detects multi-source credential stuffing targeting a single account

    from multiple distinct IP addresses within a sliding window (MITRE T1110.004).
    """

    def __init__(self, distinct_ip_threshold: int = 5, window_seconds: int = 120):
        self.threshold = distinct_ip_threshold
        self.tracker = SlidingWindowStateTracker(window_seconds=window_seconds)

    def evaluate(self, event: UnifiedAuthRecord) -> Optional[SecurityAlert]:
        if event.event_type not in (EventType.FAILED_LOGIN, EventType.INVALID_USER):
            return None

        key = event.username
        self.tracker.add_event(key=key, event=event)

        distinct_ips = {
            str(ip)
            for ip in self.tracker.get_distinct_field_values(
                key=key, field_name="source_ip", current_time=event.timestamp
            )
        }

        if len(distinct_ips) >= self.threshold:
            active_events = self.tracker.get_events(key=key, current_time=event.timestamp)
            sorted_events = sorted(active_events, key=lambda e: e.timestamp)
            return SecurityAlert(
                rule_id="SOC-RULE-004",
                rule_name="Distributed Multi-Source Brute Force",
                mitre_technique="T1110.004",
                severity="HIGH",
                source_ip="DISTRIBUTED",
                target_users=[event.username],
                event_count=len(active_events),
                first_seen=sorted_events[0].timestamp,
                last_seen=sorted_events[-1].timestamp,
                metadata={
                    "service": event.service,
                    "hostname": event.hostname,
                    "source_ips": sorted(list(distinct_ips)),
                    "distinct_ip_count": len(distinct_ips),
                },
            )

        return None
    