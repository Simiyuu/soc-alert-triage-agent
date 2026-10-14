# Autonomous SOC Alert Triage Agent

An automated Security Operations Center (SOC) detection and triage agent built in Python. The system ingests RFC-3164 authentication telemetry, clusters failed login patterns into distinct attack campaigns, enriches entities with threat intelligence, and leverages an LLM (Llama 3.3 70B via Groq) to generate actionable incident response briefs with MITRE ATT&CK mapping.

---

## Architecture Pipeline

```text
[ Raw Syslog Telemetry ]
           │
           ▼
[ Regex Ingestion & Pydantic Validation ] (RFC 3164 Parsing)
           │
           ▼
[ Aggregation & Correlation Engine ] (Threshold Brute-Force Clustering)
           │
           ▼
[ Threat Intel Enrichment ] (RFC 1918 Private LAN vs Public IP Scoring)
           │
           ▼
[ LLM Incident Triage Agent ] (Structured JSON Triage & Containment Directives)
           │
           ▼
[ SOC Incident Dossier CLI ]
```

---

## Core Capabilities

- **Strict Telemetry Validation:** Implements Pydantic v2 schemas to ensure RFC-compliant parsing of syslog timestamps, hostnames, process IDs, and IP addresses.
- **Noise Reduction & Attack Clustering:** Clusters authentication failures by source entity, measuring temporal duration and target variety to isolate brute-force activity ($O(N)$ pass).
- **Threat Intelligence Enrichment:** Distinguishes between internal lateral movement risks (RFC-1918 subnets) and external malicious scanners using IP reputation feeds.
- **Deterministic Incident Response:** Employs constrained LLM generation with fallback heuristics to generate MITRE ATT&CK technique tags (`T1110 - Brute Force`) and direct containment commands (`iptables` drops, VLAN isolation).

---

## Tech Stack

- **Language:** Python 3.10+
- **Data Modeling & Validation:** Pydantic v2
- **Testing:** Pytest
- **Inference Engine:** Groq API (`llama-3.3-70b-versatile`)
- **Telemetry Standard:** Linux Auth Syslog (RFC 3164)

---

## Project Structure

```text
soc-alert-triage-agent/
│
├── sample_data/
│   └── auth.log             
│
├── src/
│   ├── __init__.py
│   ├── models.py           
│   ├── parser.py            
│   ├── aggregator.py        
│   ├── enricher.py          
│   └── agent.py             
│
├── tests/
│   ├── __init__.py
│   └── test_parser.py       
│
├── main.py                  
├── requirements.txt        
└── README.md                
```

---

## Quickstart

### 1. Clone & Set Up Environment
```bash
git clone [https://github.com/](https://github.com/)Simiyuu/soc-alert-triage-agent.git
cd soc-alert-triage-agent
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)
Copy `.env.example` to `.env` and set your Groq API key:
```bash
GROQ_API_KEY=your_groq_api_key_here
```
*Note: The agent includes an offline deterministic fallback heuristic that executes even if an external API key is not configured.*

### 3. Run Automated Tests
```bash
py -m pytest -v
```

### 4. Execute the Triage Pipeline
```bash
py main.py sample_data/auth.log
```