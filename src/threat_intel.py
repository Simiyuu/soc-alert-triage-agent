import ipaddress
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatRecord(BaseModel):
    feed_name: str
    threat_type: str
    confidence: int = Field(ge=0, le=100)
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    matched_cidr: Optional[str] = None


class _TrieNode:
    __slots__ = ("children", "record", "cidr_str")

    def __init__(self):
        self.children: List[Optional["_TrieNode"]] = [None, None]
        self.record: Optional[ThreatRecord] = None
        self.cidr_str: Optional[str] = None


class CIDRTrie:
    """In-memory binary radix trie for sub-microsecond CIDR IP threat intelligence lookups

    with Longest Prefix Match (LPM) semantics.
    """

    def __init__(self):
        self.root = _TrieNode()
        self._count = 0

    def insert(self, cidr_str: str, record: ThreatRecord) -> None:
        """Inserts an IPv4 network prefix into the radix trie."""
        try:
            network = ipaddress.IPv4Network(cidr_str, strict=False)
        except ValueError:
            return

        node = self.root
        prefix_len = network.prefixlen
        network_int = int(network.network_address)

        # Traverse bit-by-bit from MSB down to prefixlen
        for i in range(31, 31 - prefix_len, -1):
            bit = (network_int >> i) & 1
            if node.children[bit] is None:
                node.children[bit] = _TrieNode()
            node = node.children[bit]

        # Attach record at the prefix leaf
        record_copy = record.model_copy()
        record_copy.matched_cidr = str(network)
        node.record = record_copy
        node.cidr_str = str(network)
        self._count += 1

    def lookup(self, ip_str: str) -> Optional[ThreatRecord]:
        """Performs Longest Prefix Matching (LPM) on an IPv4 address string."""
        if not ip_str or not isinstance(ip_str, str):
            return None

        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
        except ValueError:
            return None

        ip_int = int(ip_obj)
        node = self.root
        best_match: Optional[ThreatRecord] = None

        if node.record is not None:
            best_match = node.record

        # Traverse down the trie matching bits from MSB (bit 31) to LSB (bit 0)
        for i in range(31, -1, -1):
            bit = (ip_int >> i) & 1
            node = node.children[bit]
            if node is None:
                break
            if node.record is not None:
                best_match = node.record

        return best_match

    def __len__(self) -> int:
        return self._count

    @classmethod
    def from_dict_list(cls, records: List[Dict[str, Any]]) -> "CIDRTrie":
        """Factory constructor that builds and populates a trie from a list of rule dictionaries."""
        trie = cls()
        for item in records:
            cidr = item.get("cidr")
            if not cidr:
                continue
            threat = ThreatRecord(
                feed_name=item.get("feed_name", "custom_feed"),
                threat_type=item.get("threat_type", "suspicious"),
                confidence=int(item.get("confidence", 50)),
                severity=item.get("severity", "MEDIUM"),
            )
            trie.insert(cidr, threat)
        return trie
    