from typing import Any, Generator, Iterable, Optional
from src.models import EventType, SSHAuthEvent, UnifiedAuthRecord, WindowsAuthEvent
from src.parser import parse_line
from src.windows_parser import parse_windows_event


def normalize_event(event: Any) -> Optional[UnifiedAuthRecord]:
    """Normalizes typed auth events (SSHAuthEvent, WindowsAuthEvent) or raw payloads into UnifiedAuthRecord."""
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
            metadata={"process_id": event.process_id},
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
            metadata={
                "event_id": event.event_id,
                "process_id": event.process_id,
                "workstation_name": event.workstation_name,
                "sub_status": event.sub_status,
            },
        )

    if isinstance(event, str):
        parsed_ssh = parse_line(event)
        if parsed_ssh:
            return normalize_event(parsed_ssh)

    if isinstance(event, dict):
        parsed_win = parse_windows_event(event)
        if parsed_win:
            return normalize_event(parsed_win)

    return None


def stream_unified_events(records: Iterable[Any]) -> Generator[UnifiedAuthRecord, None, None]:
    """Lazy streaming generator that normalizes heterogeneous telemetry on the fly."""
    for record in records:
        normalized = normalize_event(record)
        if normalized is not None:
            yield normalized