import ipaddress
from src.models import AggregatedAlert, IPReputation, EnrichedAlert

MOCK_THREAT_INTEL_DB = {
    "203.0.113.45": {
        "score": 85,
        "country": "RU",
        "asn_org": "AS45102 BadActor Hosting LLC",
        "threat_tags": ["Known Scanner", "SSH Brute-Force Actor"],
    },
    "198.51.100.12": {
        "score": 95,
        "country": "CN",
        "asn_org": "AS12345 Bulletproof VPS",
        "threat_tags": ["Botnet Node", "Mirai Variant"],
    },
}


def lookup_ip_reputation(ip_str: str) -> IPReputation:
    # 1. Prioritize Threat Intel Feed first
    if ip_str in MOCK_THREAT_INTEL_DB:
        intel = MOCK_THREAT_INTEL_DB[ip_str]
        return IPReputation(
            ip=ip_str,
            is_private=False,
            reputation_score=intel["score"],
            country=intel["country"],
            asn_org=intel["asn_org"],
            threat_tags=intel["threat_tags"],
        )

    # 2. Check for RFC-1918 Private LAN / Loopback
    ip_obj = ipaddress.ip_address(ip_str)
    if ip_obj.is_private or ip_obj.is_loopback:
        return IPReputation(
            ip=ip_str,
            is_private=True,
            reputation_score=10,
            country="INTERNAL_LAN",
            asn_org="Private Corporate Subnet",
            threat_tags=["Internal Asset", "Potential Lateral Movement"],
        )

    # 3. Default fallback for unknown public IPs
    return IPReputation(
        ip=ip_str,
        is_private=False,
        reputation_score=40,
        country="UNKNOWN",
        asn_org="Unknown Public ISP",
        threat_tags=["Unclassified External Host"],
    )


def enrich_alerts(alerts: list[AggregatedAlert]) -> list[EnrichedAlert]:
    return [
        EnrichedAlert(alert=alert, reputation=lookup_ip_reputation(alert.source_ip))
        for alert in alerts
    ]