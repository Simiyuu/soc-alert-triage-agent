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

# =====================================================================
# v2.0 Autonomous SOC Triage Pipeline Orchestrator
# =====================================================================

from typing import List, Optional, Union
from src.asset_registry import AssetIdentityRegistry
from src.containment import ContainmentEngine, ContainmentPlan
from src.dossier import IncidentDossier, IncidentDossierGenerator
from src.models import (
    SSHAuthEvent,
    SecurityAlert,
    TriageAssessment,
    TriageVerdict,
    UnifiedAuthRecord,
    WindowsAuthEvent,
)
from src.risk_engine import RiskEngine
from src.rules_password_spray import PasswordSprayRule
from src.rules_privileged_abuse import PrivilegedAccountAbuseRule
from src.triage_engine import TriageEngine


class TriagePipeline:
    """End-to-end autonomous triage pipeline coordinating detection, scoring, containment, and reporting."""

    def __init__(
        self,
        registry: Optional[AssetIdentityRegistry] = None,
        risk_engine: Optional[RiskEngine] = None,
        triage_engine: Optional[TriageEngine] = None,
        containment_engine: Optional[ContainmentEngine] = None,
        dossier_generator: Optional[IncidentDossierGenerator] = None,
        spray_rule: Optional[PasswordSprayRule] = None,
        abuse_rule: Optional[PrivilegedAccountAbuseRule] = None,
    ) -> None:
        self.registry = registry or AssetIdentityRegistry()
        self.risk_engine = risk_engine or RiskEngine(registry=self.registry)
        self.triage_engine = triage_engine or TriageEngine(
            risk_engine=self.risk_engine, registry=self.registry
        )
        self.containment_engine = containment_engine or ContainmentEngine()
        self.dossier_generator = dossier_generator or IncidentDossierGenerator()

        # Detection rules
        self.spray_rule = spray_rule or PasswordSprayRule()
        self.abuse_rule = abuse_rule or PrivilegedAccountAbuseRule(registry=self.registry)

        # Internal state
        self._dossiers: List[IncidentDossier] = []

    def _normalize_event(
        self, event: Union[UnifiedAuthRecord, SSHAuthEvent, WindowsAuthEvent]
    ) -> UnifiedAuthRecord:
        """Converts heterogeneous auth events into standardized UnifiedAuthRecord instances."""
        if isinstance(event, UnifiedAuthRecord):
            return event
        if isinstance(event, SSHAuthEvent):
            return UnifiedAuthRecord(
                timestamp=event.timestamp,
                hostname=event.hostname,
                service="sshd",
                event_type=event.event_type,
                username=event.username,
                source_ip=event.source_ip,
                port=event.port,
                raw_reference=event.raw_log,
            )
        if isinstance(event, WindowsAuthEvent):
            return UnifiedAuthRecord(
                timestamp=event.timestamp,
                hostname=event.hostname,
                service="windows_security",
                event_type=event.event_type,
                username=event.username,
                source_ip=event.source_ip,
                port=event.port,
                logon_type=event.logon_type,
                raw_reference=str(event.raw_event) if event.raw_event else None,
            )
        raise TypeError(f"Unsupported event type: {type(event)}")

    def process_event(
        self,
        event: Union[UnifiedAuthRecord, SSHAuthEvent, WindowsAuthEvent],
        is_known_malicious: bool = False,
    ) -> List[IncidentDossier]:
        """Ingests a single event, correlates against detection rules, and returns resulting dossiers."""
        record = self._normalize_event(event)
        emitted_alerts: List[SecurityAlert] = []

        # 1. Evaluate detection rules
        spray_alert = self.spray_rule.evaluate(record)
        if spray_alert:
            emitted_alerts.append(spray_alert)

        abuse_alert = self.abuse_rule.evaluate(record)
        if abuse_alert:
            emitted_alerts.append(abuse_alert)

        # 2. Triage, contain, and compile dossiers for each triggered alert
        new_dossiers: List[IncidentDossier] = []
        for alert in emitted_alerts:
            assessment = self.triage_engine.triage(
                alert, is_known_malicious=is_known_malicious
            )
            containment_plan: Optional[ContainmentPlan] = (
                self.containment_engine.generate_plan(assessment, alert=alert)
            )

            dossier = self.dossier_generator.generate(
                assessment=assessment,
                alert=alert,
                containment_plan=containment_plan,
            )
            self._dossiers.append(dossier)
            new_dossiers.append(dossier)

        return new_dossiers
    

    def process_batch(
        self,
        events: List[Union[UnifiedAuthRecord, SSHAuthEvent, WindowsAuthEvent]],
        is_known_malicious: bool = False,
    ) -> List[IncidentDossier]:
        """Ingests an event stream and returns all generated dossiers sorted descending by risk score."""
        batch_dossiers: List[IncidentDossier] = []
        for ev in events:
            dossiers = self.process_event(ev, is_known_malicious=is_known_malicious)
            batch_dossiers.extend(dossiers)

        batch_dossiers.sort(key=lambda d: d.assessment.risk_score, reverse=True)
        return batch_dossiers

    def get_dossiers(self) -> List[IncidentDossier]:
        """Returns all historical dossiers generated during the pipeline's lifecycle."""
        return list(self._dossiers)

    def get_critical_incidents(self) -> List[IncidentDossier]:
        """Returns only dossiers flagged for CRITICAL_CONTAINMENT."""
        return [
            d for d in self._dossiers
            if d.assessment.verdict == TriageVerdict.CRITICAL_CONTAINMENT
        ]

    def clear(self) -> None:
        """Resets internal state, cleared dossiers, and resets rule sliding windows."""
        self._dossiers.clear()
        self.spray_rule.reset()
