import os
import json
from typing import Optional
from dotenv import load_dotenv
from src.models import EnrichedAlert, TriageReport, SeverityLevel

load_dotenv()

SOC_SYSTEM_PROMPT = """You are a Tier-2 Security Operations Center (SOC) Incident Responder.
Analyze the provided JSON security alert and threat intelligence context.
Evaluate attack velocity, brute-force indicators, and IP classification.

Respond ONLY with a valid, raw JSON object matching this exact schema:
{
  "alert_source_ip": "<ip_string>",
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "mitre_technique": "<MITRE ID and Name, e.g. T1110.001 - Password Guessing>",
  "threat_assessment": "<2-3 sentence technical assessment of the threat>",
  "recommended_containment": ["<action 1>", "<action 2>"],
  "escalation_required": true | false
}
Do not include markdown fences, backticks, or extra explanation outside the JSON.
"""


def _offline_fallback_triage(enriched: EnrichedAlert) -> TriageReport:
    """Deterministic fallback triage when Groq API key is unavailable."""
    alert = enriched.alert
    rep = enriched.reputation

    if alert.is_brute_force and rep.is_private:
        severity = SeverityLevel.HIGH
        assessment = (
            f"Active credential brute-force detected from internal LAN asset ({alert.source_ip}). "
            f"Targeted accounts: {alert.targeted_usernames}. Potential compromised workstation or lateral movement."
        )
        actions = [
            f"Isolate host {alert.source_ip} from internal VLAN.",
            "Force immediate password resets on targeted accounts: " + ", ".join(alert.targeted_usernames),
            "Inspect host event logs for initial access indicators."
        ]
        escalate = True
    elif alert.is_brute_force and not rep.is_private:
        severity = SeverityLevel.CRITICAL
        assessment = (
            f"External brute-force attack from known threat actor {alert.source_ip} "
            f"({rep.country}, score {rep.reputation_score})."
        )
        actions = [
            f"iptables -A INPUT -s {alert.source_ip} -j DROP",
            "Verify SSH configuration enforces key-based authentication only.",
            "Report IP to threat intelligence feed."
        ]
        escalate = True
    else:
        severity = SeverityLevel.LOW
        assessment = f"Isolated authentication failure from {alert.source_ip}. No threshold breach."
        actions = ["Continue passive monitoring. No containment necessary."]
        escalate = False

    return TriageReport(
        alert_source_ip=alert.source_ip,
        severity=severity,
        mitre_technique="T1110 - Brute Force" if alert.is_brute_force else "T1078 - Valid Accounts",
        threat_assessment=assessment,
        recommended_containment=actions,
        escalation_required=escalate,
    )


def triage_alert(enriched: EnrichedAlert, api_key: Optional[str] = None) -> TriageReport:
    """
    Executes automated LLM triage using Groq API (Llama 3.3 70B),
    falling back to deterministic evaluation if key is not configured.
    """
    key = api_key or os.getenv("GROQ_API_KEY")

    if not key:
        return _offline_fallback_triage(enriched)

    try:
        from groq import Groq

        client = Groq(api_key=key)
        payload = enriched.model_dump_json(indent=2)

        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SOC_SYSTEM_PROMPT},
                {"role": "user", "content": f"Alert Payload:\n{payload}"},
            ],
            temperature=0.1,
            response_format={"type": "json_object"},
        )

        raw_content = completion.choices[0].message.content
        data = json.loads(raw_content)
        return TriageReport(**data)

    except Exception:
        return _offline_fallback_triage(enriched)