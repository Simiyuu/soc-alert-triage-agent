# Autonomous SOC Alert Triage & Containment Platform (v2.0)

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Test Suite](https://img.shields.io/badge/pytest-126%20passed-brightgreen.svg)](tests/)
[![Architecture](https://img.shields.io/badge/architecture-autonomous--triage-orange.svg)](#architecture)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1110%20%7C%20T1078-red.svg)](https://attack.mitre.org/)

An autonomous Tier-1/Tier-2 Security Operations Center (SOC) triage, threat evaluation, and active containment platform. Built to ingest heterogeneous authentication telemetry (Linux OpenSSH syslog and Windows Event Log Security 4624/4625), correlate attacks against enterprise topology and privileged identity contexts, score incident risks via a multi-factor dynamic algorithm, and synthesize actionable containment plans across Linux, Windows, and Active Directory.

---

## Key Capabilities (v2.0 Architecture)

```text
       [ OpenSSH Syslog ]             [ Windows Event Log (4624/4625) ]
                \                                    /
                 v                                  v
              +----------------------------------------+
              | Unified Telemetry Normalization Layer  |
              +----------------------------------------+
                                  |
                                  v
              +----------------------------------------+
              | Stateful Behavioral Detection Engines  |
              |  - Horizontal Password Spray (T1110)   |
              |  - Privileged Account Abuse (T1078)    |
              +----------------------------------------+
                                  |
                                  v
              +----------------------------------------+
              | Asset & Identity Context Registry      |
              |  - Crown Jewel & Criticality Mapping   |
              |  - CIDR Zone & Admin Subnet Validation |
              +----------------------------------------+
                                  |
                                  v
              +----------------------------------------+
              | Dynamic Multi-Factor Risk Engine       |
              |  Score: 0.0 - 100.0 (Clamped)          |
              +----------------------------------------+
                                  |
                                  v
              +----------------------------------------+
              | Autonomous Triage Decision Engine      |
              |  - CRITICAL_CONTAINMENT | SUSPICIOUS   |
              |  - BENIGN_NOISE         | FALSE_POS    |
              +----------------------------------------+
                                  |
                +-----------------+-----------------+
                |                                   |
                v                                   v
+-------------------------------+   +-------------------------------+
| Automated Containment Engine  |   | Incident Dossier Generator    |
| - iptables / nftables Drops   |   | - Executive Markdown Brief    |
| - Windows Netsh / PS Rules    |   | - SIEM/SOAR JSON Payloads     |
| - AD User Account Lockout     |   | - MITRE ATT&CK Mapping        |
| - Host Micro-Segmentation     |   | - Forensic Remediation Steps  |
+-------------------------------+   +-------------------------------+
```

### 1. Unified Telemetry Normalization
Normalizes disparate authentication logs into strict `UnifiedAuthRecord` schemas, preserving logon types (Type 2 Interactive, Type 3 Network, Type 10 RemoteInteractive/RDP), source IPs, targeting metadata, and process IDs.

### 2. Behavioral Threat Detection
- **Horizontal Password Spraying (`PasswordSprayRule` - MITRE T1110.003):** Tracks unique target account cardinality per source IP over sliding time windows ($\Delta t \le 300\text{s}$) with automated cooldown suppression to eliminate alert floods.
- **Privileged Account Abuse (`PrivilegedAccountAbuseRule` - MITRE T1078.002 / T1078.004):** Flags interactive logon attempts by service accounts (`svc_*`), administrative logins originating from unauthorized source CIDRs, and off-hours sessions targeting mission-critical databases.

### 3. Context-Aware Asset & Identity Resolution
`AssetIdentityRegistry` correlates raw IPs and hostnames against organizational hierarchies:
- **Criticality Levels:** `LOW`, `MEDIUM`, `HIGH`, `MISSION_CRITICAL`.
- **Crown-Jewel Flags:** Direct identification of core ledgers, domain controllers, and key repositories.
- **CIDR Subnet Zones:** Automatic fallback classification for uncataloged hosts in known server subnets.
- **Identity Context:** Administrative privileges, executive VIP tracking, and approved source CIDR restrictions.

### 4. Multi-Factor Dynamic Risk Engine
Calculates risk on a normalized 0.0 to 100.0 scale across five weighted vectors:
1. **Base Severity:** `LOW` (20.0), `MEDIUM` (40.0), `HIGH` (65.0), `CRITICAL` (85.0).
2. **Asset Criticality:** Up to +20.0 for crown-jewel assets.
3. **Identity Privilege:** +15.0 for Admin/VIP targeting, +10.0 for Service Accounts.
4. **Volume & Velocity:** Up to +15.0 for volume ($\ge 50$ events) and +5.0 for high-velocity bursts ($\ge 10$ events in $\le 60$s).
5. **Threat Intelligence:** +15.0 for Tor exit nodes, +20.0 for verified malicious threat actors.

### 5. Automated Containment Playbooks
Translates triage verdicts into executable remediation scripts:
- **Perimeter & Host Firewall:** `iptables`, `nftables`, and Windows Advanced Firewall (`New-NetFirewallRule` / `netsh`).
- **Identity Revocation:** Active Directory lockout (`Disable-ADAccount`), token revocation (`Revoke-AzureADUserAllRefreshToken`), and Linux session termination (`passwd -l`, `pkill`).
- **Host Micro-Segmentation:** Emergency isolation policies restricting inbound/outbound communication while preserving dedicated SecOps management CIDRs (`10.50.0.0/24`).

### 6. Incident Dossier & Runbook Generation
Synthesizes comprehensive SOC incident packages exported to:
- **Markdown Runbooks:** Structured analyst briefs with executive metrics, asset impact tables, risk factor audit trails, terminal command fences, and numbered triage checklists.
- **JSON Serialization:** Direct integration schema for SIEM indexes (Splunk, Elastic) and SOAR webhooks (Cortex XSOAR, Tines).

---

## Operational Triage Matrix

| Risk Score | Verdict | Containment | Recommended Response |
| :---: | :---: | :---: | :--- |
| **$\ge$ 75.0** (or $\ge$ 60.0 on Crown Jewels) | `CRITICAL_CONTAINMENT` | **Required** | Automated IP perimeter drop, AD account lockout, host network isolation, memory artifact capture. |
| **45.0 - 74.9** | `SUSPICIOUS_REVIEW` | Manual Review | Correlate against VPN/proxy telemetry, out-of-band user verification, monitor target endpoint. |
| **< 45.0** | `BENIGN_NOISE` | None | Log and archive telemetry to data lake; no active analyst intervention required. |
| **Override** | `FALSE_POSITIVE` | Suppressed | Recognized vulnerability scan (`is_authorized_scan`) or whitelisted automation. |

---

## Directory Layout

```text
soc-alert-triage-agent/
├── benchmarks/
│   └── benchmark_triage.py         # High-volume streaming load & latency benchmark
├── src/
│   ├── asset_registry.py          # Enterprise asset & identity context registry
│   ├── containment.py             # Multi-platform firewall, AD & host containment
│   ├── dossier.py                 # Incident dossier & Markdown runbook generator
│   ├── models.py                  # Pydantic schemas, event models & enums
│   ├── parsers.py                 # OpenSSH syslog & Windows Event Log parsers
│   ├── pipeline.py                # End-to-end orchestration pipeline
│   ├── risk_engine.py             # Multi-factor dynamic risk scoring engine
│   ├── rules_password_spray.py    # Sliding-window horizontal password spray rule
│   ├── rules_privileged_abuse.py  # Service account abuse & subnet violation rule
│   └── triage_engine.py           # Autonomous verdict assignment & runbooks
├── tests/
│   ├── test_asset_registry.py
│   ├── test_containment.py
│   ├── test_context_models.py
│   ├── test_dossier.py
│   ├── test_parsers.py
│   ├── test_pipeline_v2.py
│   ├── test_risk_engine.py
│   ├── test_rules_password_spray.py
│   ├── test_rules_privileged_abuse.py
│   └── test_triage_engine.py
├── pytest.ini
├── requirements.txt
└── README.md
```

---

## Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Simiyuu/soc-alert-triage-agent.git
   cd soc-alert-triage-agent
   ```

2. **Configure Virtual Environment:**
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## Testing & Quality Assurance

The platform enforces 100% passing test requirements across all units and integration boundaries:

```bash
# Run complete test suite (126 tests)
python -m pytest

# Run with verbose reporting and execution durations
python -m pytest -v --durations=10

# Run specific functional suites
python -m pytest tests/test_pipeline_v2.py -v
python -m pytest tests/test_risk_engine.py -v
```

---

## Performance Benchmarking

A high-volume streaming benchmark tests ingestion throughput and triage latency against mixed enterprise traffic:

```bash
# Benchmark streaming triage across 5,000 synthetic events
python benchmarks/benchmark_triage.py --events 5000
```

### Benchmark Metrics (Reference Environment)
- **Ingestion Throughput:** $> 2,000$ events/second (single-threaded execution).
- **Mean Triage Latency:** $< 500\,\mu\text{s}$ per event.
- **Zero Loss:** 100% correlation fidelity on concurrent spray and privilege abuse scenarios.
