# Enterprise SOC Threat Pipeline & Behavioral Correlation Engine

An enterprise-grade, memory-efficient threat telemetry ingestion, threat intelligence enrichment, and behavioral correlation engine. Built with strict Test-Driven Development (TDD), this pipeline ingests heterogeneous Linux and Windows authentication telemetry, sanitizes against adversarial log-forging attacks, performs sub-microsecond in-memory CIDR threat lookups via Longest Prefix Matching, calculates spherical travel velocity, executes stateful sliding-window correlation rules, and dispatches deduplicated alerts to enterprise SIEM platforms (Elastic ECS 8.x and Splunk HEC).

---

## Architecture Overview

```text
       [ Linux auth.log ]               [ Windows Security EVTX / JSON ]
      (sshd RFC 5424/Legacy)                 (Event ID 4624 / 4625)
                │                                       │
                ▼                                       ▼
       [ src/parser.py ]                    [ src/windows_parser.py ]
                │                                       │
                └───────────────┬───────────────────────┘
                                │
                                ▼
                       [ src/ingest.py ]
                  (Unified Streaming Generator)
                                │
                                ▼
                      [ src/sanitizer.py ]
         (CWE-117 Strip, ANSI Scrub, NFKC Unicode Norm)
                                │
                                ▼
                    [ src/threat_intel.py ]
           (In-Memory CIDR Bitwise Radix Trie / LPM)
                                │
                                ▼
                     [ src/state_engine.py ]
         (Sliding-Window Keyed Deque Engine with Lazy TTL)
                                │
                                ▼
                       [ src/rules.py ]
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 [ Vertical Brute ]     [ Password Spray ]      [ Impossible Travel ]
   (T1110.001)             (T1110.003)           (T1078 / Haversine)
                                                        │
                                                        ▼
                                             [ Distributed Brute ]
                                                  (T1110.004)
                                │
                                ▼
                    [ src/deduplicator.py ]
         (SHA-256 Canonical Fingerprint & Suppression)
                                │
                                ▼
                     [ src/exporter.py ]
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 [ Elastic ECS 8.x ]     [ Splunk HEC ]          [ JSONL Audit Log ]
```

---

## MITRE ATT&CK Detection Matrix

| Rule ID | Rule Name | MITRE Technique | Tactics | Detection Logic & Window |
|---|---|---|---|---|
| **SOC-RULE-001** | Vertical Brute Force | **T1110.001** | Credential Access | Greater than or equal to 5 authentication failures against a single username from a single source IP within 60s. |
| **SOC-RULE-002** | Horizontal Password Spray | **T1110.003** | Credential Access | Greater than or equal to 5 distinct targeted accounts hit by a single source IP within 300s. |
| **SOC-RULE-003** | Impossible Travel | **T1078** | Defense Evasion, Initial Access | Consecutive successful logins for the same account separated by travel velocity greater than 800 km/h. |
| **SOC-RULE-004** | Distributed Multi-Source Brute Force | **T1110.004** | Credential Access | Greater than or equal to 5 distinct source IPs failing authentication against a single user within 120s. |

---

## Core Engineering Innovations

### 1. Zero-Allocation Subnet Matching (Radix Prefix Trie)
External HTTP reputation lookups introduce 50 to 200 ms of latency per record and leak sensitive corporate telemetry. This engine implements an in-memory binary radix trie (`CIDRTrie`) that indexes IPv4 network prefixes down to individual bits (MSB 31 to LSB 0).
- **Time Complexity:** O(K) where K is less than or equal to 32 bit comparisons, achieving sub-microsecond lookups (< 2 microseconds).
- **Longest Prefix Match (LPM):** Automatically selects the most granular rule (e.g., preference for a specific `/24` C2 subnet over a broad `/16` ISP range).

### 2. Great-Circle Spherical Geodesy (Haversine Formula)
To detect compromised credentials across disparate global origins, the pipeline calculates real-world distance between geographic coordinates using the spherical Haversine formula:

$$d = 2R \arcsin\left(\sqrt{\sin^2\left(\frac{\Delta \phi}{2}\right) + \cos(\phi_1)\cos(\phi_2)\sin^2\left(\frac{\Delta \lambda}{2}\right)}\right)$$

- Mean Earth radius R = 6,371.0 km.
- **Zero-Division Handling:** Simultaneous logins (delta time = 0 seconds) from distinct physical coordinates return infinite velocity (`float('inf')`), instantaneously flagging concurrent credential hijacking.
- **RFC 1918 Isolation:** Internal private IPs are resolved defensively to non-routable entities with zero false positives.

### 3. Stateful In-Memory Sliding Windows
Correlation rules rely on `SlidingWindowStateTracker`, which stores events in thread-isolated, double-ended queues (`collections.deque`) partitioned by composite pivot keys:
- **Amortized O(1) Time:** Appending new events and pruning expired records from the left of the deque takes constant time.
- **Memory Leak Protection:** State buckets are aggressively purged (`del self._state[key]`) as soon as their internal window empties.

### 4. Canonical Alert Deduplication & Cooldown Windows
During high-frequency brute-force attacks, continuous alerts induce analyst fatigue. `AlertDeduplicator` computes a deterministic SHA-256 fingerprint:

$$\text{Digest} = \text{SHA256}\Big(\text{rule\_id} \parallel \text{source\_ip} \parallel \text{sorted}(\text{target\_users})\Big)$$

- Duplicate occurrences within the configured window (e.g., 300 seconds) are suppressed.
- Upon cooldown expiration, the rule re-arms and dispatches the alert stamped with `metadata["suppressed_occurrences"]`.

### 5. Input Sanitization & CWE-117 Protection
Hostile adversaries inject payloads through authentication identities. The ingestion boundary strips:
- **ANSI Terminal Escapes:** Removes `\x1b[...]` control sequences to eliminate terminal emulation tampering.
- **Log Forging / CWE-117:** Replaces `\r\n`, `\r`, and `\n` characters with single spaces to stop log injection.
- **Unicode Homoglyphs:** Enforces NFKC Unicode normalization to collapse spoofed character variations into canonical forms.

---

## Test Suite & Verification

The pipeline is verified by **63 comprehensive automated tests** written in `pytest` with zero external dependencies:

```bash
# Execute the complete test suite with verbose execution output
python -m pytest -v

# Run with coverage enforcement
python -m pytest --cov=src --cov-report=term-missing --cov-fail-under=85
```

### Test Breakdown
- `tests/test_parser.py`: Baseline Linux SSH syslog parsing.
- `tests/test_parser_hardening.py`: RFC 5424 ISO-8601 timestamps, leap-year boundaries, boundary validation.
- `tests/test_windows_parser.py`: Windows Security Event IDs 4624 & 4625, NTSTATUS translation (`0xC0000064`, `0xC000006A`).
- `tests/test_ingest.py`: Multi-source heterogeneous streaming generator.
- `tests/test_sanitization.py`: ANSI sequence scrubbing, null-byte extraction, CWE-117 prevention.
- `tests/test_threat_intel.py`: Radix trie bitwise insertion and Longest Prefix Match resolution.
- `tests/test_geo_velocity.py`: Great-circle math, flight velocity thresholds, concurrent login edge cases.
- `tests/test_state_engine.py`: Sliding-window temporal eviction and set aggregations.
- `tests/test_rules_brute_force.py`: T1110.001 and T1110.003 correlation models.
- `tests/test_rules_impossible_travel.py`: T1078 cross-border user travel rules.
- `tests/test_rules_distributed_brute_force.py`: T1110.004 distributed credential stuffing rules.
- `tests/test_deduplicator.py`: SHA-256 fingerprinting and cooldown re-arming.
- `tests/test_exporter.py`: Elastic Common Schema (ECS 8.x), Splunk HEC, and JSONL transformations.
- `tests/test_pipeline.py`: End-to-end multi-source orchestration integration.

---

## Quickstart & CLI Usage

### Local Environment Setup

```powershell
# 1. Clone repository
git clone [https://github.com/Simiyuu/soc-threat-pipeline.git](https://github.com/Simiyuu/soc-threat-pipeline.git)
cd soc-threat-pipeline

# 2. Initialize and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install production and development dependencies
pip install -r requirements.txt
```

### Running the Executive Incident Dashboard

```powershell
# Run simulated attack stream demonstration
python -m src.main

# Process a production authentication log file
python -m src.main --input /var/log/auth.log --output-jsonl alerts.jsonl --window 300
```

### Multi-Stage Docker Container

```powershell
# Build minimal production container
docker build -t soc-threat-pipeline:latest .

# Run containerized pipeline under unprivileged UID 10001
docker run --rm -v ${PWD}/data:/app/data soc-threat-pipeline:latest --help
```

---

## SIEM Integration & Schema Support

### Elastic Common Schema (ECS 8.x)
Alerts are serialized directly into RFC-compliant ECS JSON records:
```json
{
  "@timestamp": "2026-10-26T14:30:00Z",
  "event": {
    "kind": "alert",
    "category": ["authentication"],
    "type": ["indicator"],
    "severity": 3,
    "id": "c1a6b0c2-3e28-4c12-9c90-9c1b3f9d5111"
  },
  "threat": {
    "technique": {
      "id": "T1110.001",
      "name": "Vertical Brute Force"
    }
  },
  "source": { "ip": "198.51.100.50" },
  "user": { "name": "admin", "target": ["admin"] },
  "rule": { "id": "SOC-RULE-001", "name": "Vertical Brute Force" }
}
```

### Splunk HTTP Event Collector (HEC)
Direct transmission over HTTPS using Splunk HEC envelopes with float epoch timestamps:
```json
{
  "time": 1792938600.0,
  "source": "soc-threat-pipeline",
  "sourcetype": "soc:security:alert",
  "event": {
    "alert_id": "c1a6b0c2-3e28-4c12-9c90-9c1b3f9d5111",
    "rule_name": "Vertical Brute Force",
    "mitre_technique": "T1110.001",
    "severity": "HIGH",
    "source_ip": "198.51.100.50",
    "target_users": ["admin"],
    "event_count": 5
  }
}
```

---

## Author & Engineering Standards
- **Engineer:** Chandler Matere Simiyu
- **Architecture Standard:** Python 3.11+, Pydantic v2, Flake8, Bandit SAST, Pytest-Cov
- **Target Operations:** Enterprise Cyber Defense Center (CDC), Security Operations Center (SOC) Level 2/3 Detection Engineering

