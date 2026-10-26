from collections import deque
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, List, Set
from src.models import UnifiedAuthRecord


class SlidingWindowStateTracker:
    """In-memory sliding-window state manager for real-time behavioral correlation.

    Maintains time-ordered double-ended queues keyed by arbitrary pivot strings
    (e.g., IP address, username) and performs lazy temporal eviction of stale events.
    """

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self._state: Dict[str, Deque[UnifiedAuthRecord]] = {}

    def _prune(self, key: str, current_time: datetime) -> None:
        """Evicts events older than current_time - window_seconds from the left of the deque."""
        if key not in self._state:
            return

        cutoff = current_time - timedelta(seconds=self.window_seconds)
        queue = self._state[key]

        while queue and queue[0].timestamp < cutoff:
            queue.popleft()

        if not queue:
            del self._state[key]

    def add_event(self, key: str, event: UnifiedAuthRecord) -> None:
        """Appends an event to the keyed sliding window and triggers temporal pruning."""
        if key not in self._state:
            self._state[key] = deque()

        self._state[key].append(event)
        self._prune(key, event.timestamp)

    def get_events(self, key: str, current_time: datetime) -> List[UnifiedAuthRecord]:
        """Returns all unexpired events within the active sliding window for a key."""
        self._prune(key, current_time)
        if key not in self._state:
            return []
        return list(self._state[key])

    def get_count(self, key: str, current_time: datetime) -> int:
        """Returns the number of active events within the sliding window."""
        self._prune(key, current_time)
        return len(self._state.get(key, []))

    def get_distinct_field_values(
        self, key: str, field_name: str, current_time: datetime
    ) -> Set[Any]:
        """Extracts unique values for an attribute across active events in the sliding window."""
        events = self.get_events(key, current_time)
        values: Set[Any] = set()
        for ev in events:
            val = getattr(ev, field_name, None)
            if val is not None:
                values.add(val)
        return values

    def active_keys_count(self) -> int:
        """Returns the number of currently active keyed windows in memory."""
        return len(self._state)

    def clear(self) -> None:
        """Purges all in-memory correlation state."""
        self._state.clear()
        