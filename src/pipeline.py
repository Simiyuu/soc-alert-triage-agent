from dataclasses import dataclass
from typing import Any, Iterable, List, Optional
from src.deduplicator import AlertDeduplicator
from src.ingest import normalize_event
from src.models import SecurityAlert, UnifiedAuthRecord
from src.threat_intel import CIDRTrie


@dataclass
class PipelineMetrics:
    events_ingested: int = 0
    events_dropped: int = 0
    threat_matches: int = 0
    raw_alerts_generated: int = 0
    alerts_suppressed: int = 0
    alerts_dispatched: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "events_ingested": self.events_ingested,
            "events_dropped": self.events_dropped,
            "threat_matches": self.threat_matches,
            "raw_alerts_generated": self.raw_alerts_generated,
            "alerts_suppressed": self.alerts_suppressed,
            "alerts_dispatched": self.alerts_dispatched,
        }


class PipelineOrchestrator:
    """End-to-end orchestration pipeline coordinating ingestion, sanitization,

    threat intel enrichment, stateful correlation, and alert deduplication.
    """

    def __init__(
        self,
        threat_trie: Optional[CIDRTrie] = None,
        rules: Optional[List[Any]] = None,
        deduplicator: Optional[AlertDeduplicator] = None,
    ):
        self.threat_trie = threat_trie
        self.rules = rules or []
        self.deduplicator = deduplicator
        self.metrics = PipelineMetrics()

    def process_event(self, raw_record: Any) -> List[SecurityAlert]:
        """Processes a single raw record through normalization, enrichment, and correlation."""
        normalized = normalize_event(raw_record)
        if normalized is None:
            self.metrics.events_dropped += 1
            return []

        self.metrics.events_ingested += 1

        # 1. Threat Intel Enrichment via in-memory CIDR Trie
        threat_match = None
        if self.threat_trie:
            threat_match = self.threat_trie.lookup(str(normalized.source_ip))
            if threat_match:
                self.metrics.threat_matches += 1
                normalized.metadata["threat_intel"] = threat_match.model_dump()

        dispatched: List[SecurityAlert] = []

        # 2. Behavioral Correlation Rules
        for rule in self.rules:
            alert = rule.evaluate(normalized)
            if alert:
                self.metrics.raw_alerts_generated += 1

                # Propagate threat intel into alert metadata if available
                if threat_match:
                    alert.metadata["threat_intel"] = threat_match.model_dump()

                # 3. Deduplication and Suppression
                if self.deduplicator:
                    emitted = self.deduplicator.process(alert)
                    if emitted is None:
                        self.metrics.alerts_suppressed += 1
                        continue
                    alert = emitted

                self.metrics.alerts_dispatched += 1
                dispatched.append(alert)

        return dispatched

    def process_stream(self, records: Iterable[Any]) -> List[SecurityAlert]:
        """Streams an iterable of raw records through the entire pipeline and collects dispatched alerts."""
        all_dispatched: List[SecurityAlert] = []
        for record in records:
            dispatched = self.process_event(record)
            all_dispatched.extend(dispatched)
        return all_dispatched
    