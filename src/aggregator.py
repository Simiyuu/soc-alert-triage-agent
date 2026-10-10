from collections import defaultdict
from typing import List, Dict
from datetime import datetime
from src.models import SSHAuthEvent, EventType, AggregatedAlert


def aggregate_events(
    events: List[SSHAuthEvent], 
    threshold: int = 3
) -> List[AggregatedAlert]:
    """
    Groups SSH authentication failures by source IP and flags brute-force patterns
    exceeding the specified failure threshold.
    """
    failures_by_ip: Dict[str, List[SSHAuthEvent]] = defaultdict(list)

    for event in events:
        if event.event_type in (EventType.FAILED_LOGIN, EventType.INVALID_USER):
            failures_by_ip[str(event.source_ip)].append(event)

    alerts: List[AggregatedAlert] = []

    for ip, ip_events in failures_by_ip.items():
        total_failures = len(ip_events)
        
        ip_events.sort(key=lambda x: x.timestamp)
        first_seen = ip_events[0].timestamp
        last_seen = ip_events[-1].timestamp
        duration = (last_seen - first_seen).total_seconds()

        targeted_users = sorted(list({e.username for e in ip_events}))
        
        is_brute = total_failures >= threshold

        summary = (
            f"Detected {total_failures} failed login attempts from {ip} "
            f"targeting accounts {targeted_users} across {duration:.1f} seconds."
        )

        alerts.append(
            AggregatedAlert(
                source_ip=ip,
                total_failures=total_failures,
                targeted_usernames=targeted_users,
                first_seen=first_seen,
                last_seen=last_seen,
                duration_seconds=duration,
                is_brute_force=is_brute,
                summary=summary,
            )
        )

    return sorted(alerts, key=lambda a: a.total_failures, reverse=True)