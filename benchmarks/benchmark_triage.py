import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import random
import sys
import time
from typing import List, Tuple

# Ensure repository root is on sys.path for direct script execution
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.asset_registry import AssetIdentityRegistry
from src.models import (
    AssetContext,
    CriticalityLevel,
    EventType,
    TriageVerdict,
    UnifiedAuthRecord,
    UserContext,
    UserRole,
)
from src.pipeline import TriagePipeline
from src.rules_password_spray import PasswordSprayRule
from src.rules_privileged_abuse import PrivilegedAccountAbuseRule


def setup_benchmark_environment() -> Tuple[TriagePipeline, AssetIdentityRegistry]:
    """Configures a populated enterprise topology for benchmark runs."""
    registry = AssetIdentityRegistry()

    # Core Assets
    registry.register_asset(
        AssetContext(
            hostname="core-swift-db01.corp",
            ip_address="10.100.4.50",
            criticality=CriticalityLevel.MISSION_CRITICAL,
            business_unit="Core Banking Operations",
            is_crown_jewel=True,
            environment="production",
        )
    )
    registry.register_asset(
        AssetContext(
            hostname="ad-dc01.corp",
            ip_address="10.100.1.10",
            criticality=CriticalityLevel.MISSION_CRITICAL,
            business_unit="Identity & Access",
            is_crown_jewel=True,
            environment="production",
        )
    )
    registry.register_asset(
        AssetContext(
            hostname="jump-host01.corp",
            ip_address="192.168.10.15",
            criticality=CriticalityLevel.HIGH,
            business_unit="Security Operations",
            is_crown_jewel=False,
            environment="production",
        )
    )

    # Subnet Zones
    registry.register_subnet_zone(
        cidr="172.16.0.0/16",
        criticality=CriticalityLevel.MEDIUM,
        business_unit="Corporate Workstations",
        is_crown_jewel=False,
    )
    registry.register_subnet_zone(
        cidr="10.100.0.0/16",
        criticality=CriticalityLevel.HIGH,
        business_unit="Datacenter Server Farm",
        is_crown_jewel=True,
    )

    # Identities
    registry.register_user(
        UserContext(
            username="secops_admin",
            role=UserRole.PRIVILEGED_ADMIN,
            department="Information Security",
            is_vip=True,
            approved_source_subnets=["192.168.10.0/24"],
        )
    )
    registry.register_user(
        UserContext(
            username="svc_core_sync",
            role=UserRole.SERVICE_ACCOUNT,
            department="Core Infrastructure",
            is_vip=False,
            approved_source_subnets=["10.100.4.0/24"],
        )
    )
    registry.register_user(
        UserContext(
            username="ciso_exec",
            role=UserRole.EXECUTIVE_VIP,
            department="Executive Office",
            is_vip=True,
            approved_source_subnets=[],
        )
    )

    pipeline = TriagePipeline(
        registry=registry,
        spray_rule=PasswordSprayRule(user_threshold=5, window_seconds=300, alert_cooldown_seconds=120),
        abuse_rule=PrivilegedAccountAbuseRule(registry=registry, business_hours_start=6, business_hours_end=20),
    )

    return pipeline, registry


def generate_synthetic_telemetry(total_events: int) -> List[UnifiedAuthRecord]:
    """Generates synthetic authentication logs mixing benign events, sprays, and privilege abuse."""
    events: List[UnifiedAuthRecord] = []
    base_time = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)

    standard_users = [f"emp_user_{i:03d}" for i in range(1, 60)]
    attacker_ips = [f"198.51.100.{i}" for i in range(10, 25)]
    corporate_ips = [f"172.16.50.{i}" for i in range(1, 150)]

    for i in range(total_events):
        event_time = base_time + timedelta(milliseconds=i * 200)
        roll = random.random()

        if roll < 0.85:
            # 85% Benign daytime authentication traffic
            events.append(
                UnifiedAuthRecord(
                    timestamp=event_time,
                    hostname="jump-host01.corp" if random.random() < 0.3 else f"workstation-{i % 50}.corp",
                    service="sshd" if random.random() < 0.5 else "windows_security",
                    event_type=EventType.ACCEPTED_LOGIN if random.random() < 0.95 else EventType.FAILED_LOGIN,
                    username=random.choice(standard_users),
                    source_ip=random.choice(corporate_ips),
                    port=22 if random.random() < 0.5 else 445,
                    logon_type=2 if random.random() < 0.5 else 3,
                )
            )
        elif roll < 0.95:
            # 10% Horizontal Password Spray attack
            events.append(
                UnifiedAuthRecord(
                    timestamp=event_time,
                    hostname="jump-host01.corp",
                    service="sshd",
                    event_type=EventType.FAILED_LOGIN,
                    username=random.choice(standard_users),
                    source_ip=random.choice(attacker_ips),
                    port=22,
                )
            )
        else:
            # 5% Privileged Account Abuse on Core Banking & Domain Controller
            target_host = "core-swift-db01.corp" if random.random() < 0.6 else "ad-dc01.corp"
            events.append(
                UnifiedAuthRecord(
                    timestamp=event_time.replace(hour=2),  # Off-hours (02:00 UTC)
                    hostname=target_host,
                    service="windows_security",
                    event_type=EventType.ACCEPTED_LOGIN,
                    username="svc_core_sync" if random.random() < 0.5 else "secops_admin",
                    source_ip="203.0.113.88",  # Rogue external unapproved IP
                    port=445,
                    logon_type=2,  # Interactive logon violation
                )
            )

    return events


def run_benchmark(total_events: int) -> None:
    """Executes the streaming ingestion benchmark and prints performance statistics."""
    print("=" * 70)
    print("  SOC ALERT TRIAGE AGENT v2.0 - HIGH-VOLUME STREAMING BENCHMARK")
    print("=" * 70)
    print(f"[*] Generating {total_events:,} synthetic authentication records...")

    events = generate_synthetic_telemetry(total_events)
    pipeline, _ = setup_benchmark_environment()

    print(f"[*] Streaming {len(events):,} events through TriagePipeline...")

    start_time = time.perf_counter()
    all_dossiers = []

    for event in events:
        dossiers = pipeline.process_event(event)
        if dossiers:
            all_dossiers.extend(dossiers)

    elapsed_time = time.perf_counter() - start_time
    events_per_sec = total_events / elapsed_time if elapsed_time > 0 else 0.0
    latency_per_event_us = (elapsed_time / total_events) * 1_000_000

    # Verdict aggregation
    verdict_counts = {
        TriageVerdict.CRITICAL_CONTAINMENT: 0,
        TriageVerdict.SUSPICIOUS_REVIEW: 0,
        TriageVerdict.BENIGN_NOISE: 0,
        TriageVerdict.FALSE_POSITIVE: 0,
    }

    for d in all_dossiers:
        verdict_counts[d.assessment.verdict] = verdict_counts.get(d.assessment.verdict, 0) + 1

    containment_plans_count = sum(
        1 for d in all_dossiers if d.containment_plan and d.containment_plan.requires_containment
    )

    print("\n" + "=" * 70)
    print("  BENCHMARK EXECUTION RESULTS")
    print("=" * 70)
    print(f" Total Ingested Events:         {total_events:,}")
    print(f" Total Processing Time:         {elapsed_time:.3f} seconds")
    print(f" Ingestion Throughput:          {events_per_sec:,.1f} events/sec")
    print(f" Mean Ingestion Latency:        {latency_per_event_us:.2f} us/event")
    print("-" * 70)
    print("  TRIAGE OUTCOME & DOSSIER GENERATION")
    print("-" * 70)
    print(f" Total Incidents Triaged:       {len(all_dossiers):,}")
    print(f" - CRITICAL_CONTAINMENT:        {verdict_counts[TriageVerdict.CRITICAL_CONTAINMENT]:,}")
    print(f" - SUSPICIOUS_REVIEW:           {verdict_counts[TriageVerdict.SUSPICIOUS_REVIEW]:,}")
    print(f" - BENIGN_NOISE:                {verdict_counts[TriageVerdict.BENIGN_NOISE]:,}")
    print(f" - FALSE_POSITIVE:              {verdict_counts[TriageVerdict.FALSE_POSITIVE]:,}")
    print(f" Active Containment Playbooks:  {containment_plans_count:,}")
    print("=" * 70)
    print("[+] Benchmark completed successfully.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run SOC Alert Triage Pipeline Benchmark")
    parser.add_argument(
        "--events",
        type=int,
        default=5000,
        help="Number of synthetic events to process (default: 5000)",
    )
    args = parser.parse_args()
    run_benchmark(total_events=args.events)
    