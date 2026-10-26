from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from src.deduplicator import AlertDeduplicator
from src.models import EventType, SecurityAlert
from src.pipeline import PipelineOrchestrator
from src.rules import (
    DistributedBruteForceRule,
    HorizontalPasswordSprayRule,
    ImpossibleTravelRule,
    VerticalBruteForceRule,
)
from src.threat_intel import CIDRTrie, ThreatRecord


@pytest.fixture
def configured_orchestrator():
    # 1. Setup Threat Intel Trie
    trie = CIDRTrie()
    trie.insert(
        "198.51.100.0/24",
        ThreatRecord(
            feed_name="EmergingThreats_Compromised",
            threat_type="Malicious_Infrastructure",
            confidence=95,
            severity="HIGH",
        ),
    )

    # 2. Setup Behavioral Rules
    rules = [
        VerticalBruteForceRule(failure_threshold=3, window_seconds=60),
        HorizontalPasswordSprayRule(distinct_user_threshold=3, window_seconds=300),
        ImpossibleTravelRule(speed_threshold_kmh=800.0),
        DistributedBruteForceRule(distinct_ip_threshold=3, window_seconds=120),
    ]

    # 3. Setup Deduplicator
    deduplicator = AlertDeduplicator(suppression_window_seconds=300)

    return PipelineOrchestrator(
        threat_trie=trie,
        rules=rules,
        deduplicator=deduplicator,
    )


def test_pipeline_vertical_brute_force_with_threat_intel_enrichment(configured_orchestrator):
    """Verify raw syslog lines flow through, trigger brute force, and enrich with threat intel."""
    base_time = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)
    raw_logs = [
        f"Oct 25 14:00:0{i} srv-01 sshd[100]: Failed password for admin from 198.51.100.25 port {40000 + i} ssh2"
        for i in range(3)
    ]

    dispatched_alerts = configured_orchestrator.process_stream(raw_logs)

    assert len(dispatched_alerts) == 1
    alert = dispatched_alerts[0]
    assert alert.rule_id == "SOC-RULE-001"
    assert alert.source_ip == "198.51.100.25"
    assert alert.target_users == ["admin"]

    # Verify Threat Intel enrichment from CIDR Trie
    assert "threat_intel" in alert.metadata
    assert alert.metadata["threat_intel"]["feed_name"] == "EmergingThreats_Compromised"
    assert alert.metadata["threat_intel"]["confidence"] == 95

    # Verify metrics
    metrics = configured_orchestrator.metrics
    assert metrics.events_ingested == 3
    assert metrics.threat_matches == 3
    assert metrics.raw_alerts_generated == 1
    assert metrics.alerts_dispatched == 1
    assert metrics.alerts_suppressed == 0


def test_pipeline_deduplication_suppresses_alert_flood(configured_orchestrator):
    """Verify continuous brute force attacks trigger the initial alert but suppress duplicates."""
    base_time = datetime(2026, 10, 25, 14, 0, 0, tzinfo=timezone.utc)

    # 8 rapid failure attempts (threshold is 3)
    raw_logs = [
        f"Oct 25 14:00:{i:02d} srv-01 sshd[100]: Failed password for root from 198.51.100.50 port 50000 ssh2"
        for i in range(8)
    ]

    dispatched_alerts = configured_orchestrator.process_stream(raw_logs)

    # Only 1 unique alert should be dispatched; remaining 5 should be suppressed
    assert len(dispatched_alerts) == 1
    metrics = configured_orchestrator.metrics
    assert metrics.events_ingested == 8
    assert metrics.raw_alerts_generated >= 2
    assert metrics.alerts_suppressed >= 1
    assert metrics.alerts_dispatched == 1


def test_pipeline_mixed_stream_with_adversarial_poison_pills(configured_orchestrator):
    """Verify malformed records, ANSI injections, and non-auth lines are safely discarded without halting execution."""
    mixed_stream = [
        "Oct 25 14:00:01 srv-01 sshd[100]: Invalid user \x1b[31;1madmin\x1b[0m\x00 from 198.51.100.10 port 41001 ssh2",
        "Corrupted unparseable syslog garbage line",
        {"Event": {"System": {"EventID": 9999}}},  # Unrelated event ID
        "",  # Empty payload
        "Oct 25 14:00:02 srv-01 sshd[100]: Invalid user admin from 198.51.100.10 port 41002 ssh2",
        "Oct 25 14:00:03 srv-01 sshd[100]: Invalid user admin from 198.51.100.10 port 41003 ssh2",
    ]

    dispatched = configured_orchestrator.process_stream(mixed_stream)

    assert len(dispatched) == 1
    assert dispatched[0].target_users == ["admin"]
    assert configured_orchestrator.metrics.events_dropped >= 2
    assert configured_orchestrator.metrics.events_ingested == 3


def test_pipeline_impossible_travel_cross_border(configured_orchestrator):
    """Verify end-to-end impossible travel correlation across Nairobi and London logins."""
    stream = [
        {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "TimeCreated": {"SystemTime": "2026-10-25T14:00:00Z"},
                    "Computer": "DC01.corp.internal",
                    "Execution": {"ProcessID": 500},
                },
                "EventData": {
                    "TargetUserName": "charlie_cdc",
                    "WorkstationName": "NBO-WORKSTATION",
                    "IpAddress": "197.237.100.1",  # Nairobi
                    "IpPort": "54321",
                    "LogonType": 10,
                },
            }
        },
        {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "TimeCreated": {"SystemTime": "2026-10-25T14:10:00Z"},
                    "Computer": "DC01.corp.internal",
                    "Execution": {"ProcessID": 501},
                },
                "EventData": {
                    "TargetUserName": "charlie_cdc",
                    "WorkstationName": "LON-WORKSTATION",
                    "IpAddress": "81.2.69.142",  # London
                    "IpPort": "54322",
                    "LogonType": 10,
                },
            }
        },
    ]

    dispatched = configured_orchestrator.process_stream(stream)

    assert len(dispatched) == 1
    assert dispatched[0].rule_id == "SOC-RULE-003"
    assert dispatched[0].target_users == ["charlie_cdc"]
    assert dispatched[0].metadata["origin_city"] == "Nairobi"
    assert dispatched[0].metadata["target_city"] == "London"
    