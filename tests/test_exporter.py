import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from src.exporter import (
    dispatch_http_alert,
    export_to_jsonl,
    to_ecs_format,
    to_splunk_hec_format,
)
from src.models import SecurityAlert


@pytest.fixture
def sample_alert() -> SecurityAlert:
    return SecurityAlert(
        alert_id="c1a6b0c2-3e28-4c12-9c90-9c1b3f9d5111",
        timestamp=datetime(2026, 10, 25, 14, 30, 0, tzinfo=timezone.utc),
        rule_id="SOC-RULE-001",
        rule_name="Vertical Brute Force",
        mitre_technique="T1110.001",
        severity="HIGH",
        source_ip="198.51.100.50",
        target_users=["admin"],
        event_count=5,
        first_seen=datetime(2026, 10, 25, 14, 29, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 10, 25, 14, 30, 0, tzinfo=timezone.utc),
        metadata={"service": "sshd", "hostname": "bastion-01"},
    )


def test_to_ecs_format(sample_alert):
    """Verify conversion to Elastic Common Schema (ECS 8.x)."""
    ecs = to_ecs_format(sample_alert)

    assert ecs["@timestamp"] == "2026-10-25T14:30:00Z"
    assert ecs["event"]["kind"] == "alert"
    assert ecs["event"]["category"] == ["authentication"]
    assert ecs["event"]["type"] == ["indicator"]
    assert ecs["event"]["severity"] == 3  # High severity mapped to 3
    assert ecs["threat"]["technique"]["id"] == "T1110.001"
    assert ecs["threat"]["technique"]["name"] == "Vertical Brute Force"
    assert ecs["source"]["ip"] == "198.51.100.50"
    assert ecs["user"]["name"] == "admin"
    assert ecs["host"]["name"] == "bastion-01"


def test_to_splunk_hec_format(sample_alert):
    """Verify conversion to Splunk HTTP Event Collector format."""
    hec = to_splunk_hec_format(sample_alert)

    assert hec["time"] == sample_alert.timestamp.timestamp()
    assert hec["source"] == "soc-threat-pipeline"
    assert hec["sourcetype"] == "soc:security:alert"
    assert hec["event"]["alert_id"] == "c1a6b0c2-3e28-4c12-9c90-9c1b3f9d5111"
    assert hec["event"]["rule_name"] == "Vertical Brute Force"
    assert hec["event"]["mitre_technique"] == "T1110.001"


def test_export_to_jsonl(tmp_path: Path, sample_alert):
    """Verify appending alerts to newline-delimited JSON."""
    out_file = tmp_path / "alerts.jsonl"
    alerts = [sample_alert, sample_alert]

    export_to_jsonl(alerts, str(out_file))

    lines = out_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    parsed_line = json.loads(lines[0])
    assert parsed_line["rule_id"] == "SOC-RULE-001"
    assert parsed_line["source_ip"] == "198.51.100.50"


def test_dispatch_http_alert_sends_post(sample_alert, mocker):
    """Verify HTTP dispatcher constructs proper headers and body."""
    mock_post = mocker.patch("requests.post")
    mock_post.return_value.status_code = 200

    url = "https://siem.corp.internal/services/collector"
    token = "Splunk 12345678-ABCD-EF01-2345"

    success = dispatch_http_alert(
        alert=sample_alert,
        endpoint=url,
        auth_header=token,
        schema="splunk",
    )

    assert success is True
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == url
    assert kwargs["headers"]["Authorization"] == token
    assert kwargs["headers"]["Content-Type"] == "application/json"
    body = json.loads(kwargs["data"])
    assert body["sourcetype"] == "soc:security:alert"
    