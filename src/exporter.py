import json
from datetime import datetime
from typing import Any, Dict, List
import requests
from src.models import SecurityAlert

SEVERITY_TO_ECS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def to_ecs_format(alert: SecurityAlert) -> Dict[str, Any]:
    """Serializes a SecurityAlert into Elastic Common Schema (ECS 8.x) format."""
    ecs_ts = alert.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

    ecs_doc: Dict[str, Any] = {
        "@timestamp": ecs_ts,
        "event": {
            "kind": "alert",
            "category": ["authentication"],
            "type": ["indicator"],
            "severity": SEVERITY_TO_ECS.get(alert.severity.upper(), 1),
            "id": alert.alert_id,
            "start": alert.first_seen.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": alert.last_seen.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "threat": {
            "technique": {
                "id": alert.mitre_technique,
                "name": alert.rule_name,
            }
        },
        "source": {
            "ip": alert.source_ip,
        },
        "user": {
            "name": alert.target_users[0] if alert.target_users else "unknown",
            "target": alert.target_users,
        },
        "rule": {
            "id": alert.rule_id,
            "name": alert.rule_name,
        },
        "soc_pipeline": {
            "event_count": alert.event_count,
            "metadata": alert.metadata,
        },
    }

    hostname = alert.metadata.get("hostname")
    if hostname:
        ecs_doc["host"] = {"name": hostname}

    return ecs_doc


def to_splunk_hec_format(alert: SecurityAlert) -> Dict[str, Any]:
    """Serializes a SecurityAlert into Splunk HTTP Event Collector (HEC) format."""
    return {
        "time": alert.timestamp.timestamp(),
        "source": "soc-threat-pipeline",
        "sourcetype": "soc:security:alert",
        "event": {
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp.isoformat(),
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "mitre_technique": alert.mitre_technique,
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "target_users": alert.target_users,
            "event_count": alert.event_count,
            "first_seen": alert.first_seen.isoformat(),
            "last_seen": alert.last_seen.isoformat(),
            "metadata": alert.metadata,
        },
    }


def export_to_jsonl(alerts: List[SecurityAlert], file_path: str) -> None:
    """Appends alerts as newline-delimited JSON (JSONL) records to a local file."""
    with open(file_path, "a", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert.model_dump(mode="json")) + "\n")


def dispatch_http_alert(
    alert: SecurityAlert,
    endpoint: str,
    auth_header: str,
    schema: str = "ecs",
    timeout_seconds: float = 5.0,
) -> bool:
    """Dispatches a SecurityAlert over HTTP/S to a SIEM collector endpoint."""
    headers = {
        "Authorization": auth_header,
        "Content-Type": "application/json",
    }

    if schema.lower() == "splunk":
        payload = to_splunk_hec_format(alert)
    else:
        payload = to_ecs_format(alert)

    try:
        response = requests.post(
            endpoint,
            data=json.dumps(payload),
            headers=headers,
            timeout=timeout_seconds,
        )
        return 200 <= response.status_code < 300
    except requests.RequestException:
        return False
    