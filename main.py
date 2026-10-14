import sys
from pathlib import Path
from src.parser import parse_log_file
from src.aggregator import aggregate_events
from src.enricher import enrich_alerts
from src.agent import triage_alert


def print_banner():
    print("=" * 70)
    print("          SOC AUTOMATION AGENT - SSH INCIDENT TRIAGE          ")
    print("=" * 70)


def run_pipeline(log_path: str, threshold: int = 3):
    path = Path(log_path)
    if not path.exists():
        print(f"[!] Error: Log file not found at '{log_path}'")
        sys.exit(1)

    print_banner()
    print(f"[*] Ingesting raw telemetry: {log_path}")
    events = parse_log_file(str(path))
    print(f"[+] Ingestion complete: Parsed {len(events)} security events.")

    print(f"\n[*] Aggregating failures (Threshold: {threshold} attempts)...")
    alerts = aggregate_events(events, threshold=threshold)
    print(f"[+] Aggregation complete: Clustered into {len(alerts)} entity alerts.")

    print("\n[*] Enriching alerts with threat intelligence feeds...")
    enriched = enrich_alerts(alerts)

    print("\n[*] Running automated incident triage...")
    reports = [triage_alert(e) for e in enriched]

    print("\n" + "=" * 70)
    print("                     INCIDENT TRIAGE DOSSIER                    ")
    print("=" * 70)

    for idx, report in enumerate(reports, 1):
        color_flag = "[CRITICAL]" if report.severity.value in ("HIGH", "CRITICAL") else "[INFO]"
        print(f"\n--- Incident #{idx} {color_flag} Source: {report.alert_source_ip} ---")
        print(f"Severity Level      : {report.severity.value}")
        print(f"MITRE ATT&CK        : {report.mitre_technique}")
        print(f"Escalation Required : {'YES' if report.escalation_required else 'NO'}")
        print(f"Assessment          :\n  {report.threat_assessment}")
        print("Recommended Containment:")
        for action in report.recommended_containment:
            print(f"  [>] {action}")

    print("\n" + "=" * 70)
    print("                      PIPELINE EXECUTION COMPLETE                ")
    print("=" * 70)


if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else "sample_data/auth.log"
    run_pipeline(target_file)
    