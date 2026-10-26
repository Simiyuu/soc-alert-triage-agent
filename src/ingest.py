from typing import Any, Generator, Iterable, Optional
from src.models import EventType, SSHAuthEvent, UnifiedAuthRecord, WindowsAuthEvent
from src.parser import parse_line
from src.sanitizer import sanitize_auth_record
from src.windows_parser import parse_windows_event


def normalize_event(event: Any) -> Optional[UnifiedAuthRecord]:
    """Normalizes typed auth events or raw payloads into a sanitized UnifiedAuthRecord."""
    record: Optional[UnifiedAuthRecord] = None

    if isinstance(event, SSHAuthEvent):
        record = UnifiedAuthRecord(
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

    elif isinstance(event, WindowsAuthEvent):
        record = UnifiedAuthRecord(
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

    elif isinstance(event, str):
        parsed_ssh = parse_line(event)
        if parsed_ssh:
            return normalize_event(parsed_ssh)

    elif isinstance(event, dict):
        parsed_win = parse_windows_event(event)
        if parsed_win:
            return normalize_event(parsed_win)

    if record is not None:
        return sanitize_auth_record(record)

    return None


def stream_unified_events(records: Iterable[Any]) -> Generator[UnifiedAuthRecord, None, None]:
    """Lazy streaming generator that normalizes and sanitizes heterogeneous telemetry on the fly."""
    for record in records:
        normalized = normalize_event(record)
        if normalized is not None:
            yield normalized