import ipaddress
import pytest
from src.threat_intel import CIDRTrie, ThreatRecord


@pytest.fixture
def sample_trie():
    trie = CIDRTrie()
    trie.insert("185.220.101.0/24", ThreatRecord(
        feed_name="Tor_Exit_Nodes",
        threat_type="Anonymizer",
        confidence=95,
        severity="MEDIUM"
    ))
    trie.insert("198.51.100.15/32", ThreatRecord(
        feed_name="Known_C2_Drop",
        threat_type="Botnet_C2",
        confidence=100,
        severity="CRITICAL"
    ))
    # Overlapping broader subnet for LPM testing
    trie.insert("185.220.0.0/16", ThreatRecord(
        feed_name="Shady_ISP_Alloc",
        threat_type="Suspicious_Infrastructure",
        confidence=40,
        severity="LOW"
    ))
    return trie


def test_exact_ip_match(sample_trie):
    """Verify an exact /32 match returns the highest confidence threat record."""
    match = sample_trie.lookup("198.51.100.15")
    assert match is not None
    assert match.threat_type == "Botnet_C2"
    assert match.confidence == 100
    assert match.severity == "CRITICAL"
    assert match.matched_cidr == "198.51.100.15/32"


def test_subnet_containment_match(sample_trie):
    """Verify an IP within a /24 subnet correctly flags the parent threat block."""
    match = sample_trie.lookup("185.220.101.77")
    assert match is not None
    assert match.feed_name == "Tor_Exit_Nodes"
    assert match.threat_type == "Anonymizer"
    assert match.matched_cidr == "185.220.101.0/24"


def test_longest_prefix_match_precedence(sample_trie):
    """Verify LPM selects the more specific /24 over the broader /16 block."""
    # 185.220.101.5 belongs to both 185.220.0.0/16 and 185.220.101.0/24
    match = sample_trie.lookup("185.220.101.5")
    assert match is not None
    assert match.matched_cidr == "185.220.101.0/24"
    assert match.feed_name == "Tor_Exit_Nodes"

    # 185.220.99.1 belongs only to 185.220.0.0/16
    match_broad = sample_trie.lookup("185.220.99.1")
    assert match_broad is not None
    assert match_broad.matched_cidr == "185.220.0.0/16"
    assert match_broad.feed_name == "Shady_ISP_Alloc"


def test_clean_and_private_ips_return_none(sample_trie):
    """Verify benign and RFC 1918 IPs yield no threat matches."""
    assert sample_trie.lookup("10.0.0.1") is None
    assert sample_trie.lookup("192.168.1.100") is None
    assert sample_trie.lookup("8.8.8.8") is None


def test_invalid_ip_returns_none_defensively(sample_trie):
    """Verify malformed or invalid IP strings fail defensively without raising exceptions."""
    assert sample_trie.lookup("invalid_ip") is None
    assert sample_trie.lookup("999.999.999.999") is None
    assert sample_trie.lookup("") is None


def test_bulk_load_from_dict_list():
    """Verify bulk ingestion of rules into a new trie instance."""
    raw_feed = [
        {"cidr": "203.0.113.0/24", "feed_name": "Scanner_Feed", "threat_type": "Scanner", "confidence": 80, "severity": "MEDIUM"},
        {"cidr": "198.51.100.0/24", "feed_name": "Malware_Feed", "threat_type": "Malware", "confidence": 90, "severity": "HIGH"},
    ]
    trie = CIDRTrie.from_dict_list(raw_feed)
    assert len(trie) == 2
    match = trie.lookup("203.0.113.45")
    assert match is not None
    assert match.feed_name == "Scanner_Feed"