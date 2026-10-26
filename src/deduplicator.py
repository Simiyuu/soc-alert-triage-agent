import hashlib
from datetime import datetime
from typing import Dict, Optional
from src.models import SecurityAlert


class _DeduplicationState:
    __slots__ = ("last_emitted", "suppressed_count")

    def __init__(self, last_emitted: datetime):
        self.last_emitted = last_emitted
        self.suppressed_count = 0


class AlertDeduplicator:
    """Fingerprints incoming SecurityAlert objects and suppresses duplicates

    within a configurable sliding time window.
    """

    def __init__(self, suppression_window_seconds: int = 600):
        self.suppression_window_seconds = suppression_window_seconds
        self._cache: Dict[str, _DeduplicationState] = {}

    def compute_fingerprint(self, alert: SecurityAlert) -> str:
        """Generates a deterministic SHA-256 fingerprint for an alert based on rule, source, and users."""
        canonical_users = ",".join(sorted(alert.target_users))
        raw_key = f"{alert.rule_id}|{alert.source_ip}|{canonical_users}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def is_suppressed(self, alert: SecurityAlert) -> bool:
        """Checks if an alert fingerprint is currently within an active suppression window."""
        fp = self.compute_fingerprint(alert)
        state = self._cache.get(fp)
        if not state:
            return False

        delta = (alert.last_seen - state.last_emitted).total_seconds()
        return delta < self.suppression_window_seconds

    def get_suppressed_count(self, alert: SecurityAlert) -> int:
        """Returns the number of suppressed duplicate occurrences for an alert."""
        fp = self.compute_fingerprint(alert)
        state = self._cache.get(fp)
        return state.suppressed_count if state else 0

    def process(self, alert: SecurityAlert) -> Optional[SecurityAlert]:
        """Evaluates an alert against active suppression windows.

        Returns the alert (optionally enriched with suppressed count metadata)
        if it should be emitted, or None if it is suppressed.
        """
        fp = self.compute_fingerprint(alert)
        state = self._cache.get(fp)

        if state is None:
            # First time seeing this fingerprint
            self._cache[fp] = _DeduplicationState(last_emitted=alert.last_seen)
            return alert

        delta = (alert.last_seen - state.last_emitted).total_seconds()

        if delta < self.suppression_window_seconds:
            # Active window: suppress and increment counter
            state.suppressed_count += 1
            return None

        # Window expired: re-arm and emit
        emitted_alert = alert.model_copy(deep=True)
        if state.suppressed_count > 0:
            emitted_alert.metadata["suppressed_occurrences"] = state.suppressed_count

        self._cache[fp] = _DeduplicationState(last_emitted=alert.last_seen)
        return emitted_alert

    def clear(self) -> None:
        """Clears all deduplication state."""
        self._cache.clear()
        