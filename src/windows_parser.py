from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import ValidationError
from src.models import EventType, WindowsAuthEvent


def parse_windows_event(event_dict: Dict[str, Any]) -> Optional[WindowsAuthEvent]:
    """Defensively normalizes Windows Event ID 4624/4625 dictionaries into WindowsAuthEvent."""
    try:
        event = event_dict.get("Event", {})
        system = event.get("System", {})
        event_id = int(system.get("EventID", 0))

        if event_id not in (4624, 4625):
            return None

        event_data = event.get("EventData", {})
        ip_str = event_data.get("IpAddress")
        if not ip_str or ip_str in ("-", ""):
            return None

        port_str = event_data.get("IpPort", "")
        if not port_str or port_str == "-":
            return None

        port = int(port_str)
        if not (1 <= port <= 65535):
            return None

        # Parse UTC timestamp from SystemTime
        raw_time = system.get("TimeCreated", {}).get("SystemTime")
        if not raw_time:
            return None

        if raw_time.endswith("Z"):
            dt = datetime.fromisoformat(raw_time[:-1]).replace(tzinfo=timezone.utc)
        else:
            dt = datetime.fromisoformat(raw_time)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

        # Normalize NTSTATUS failure codes
        sub_status = event_data.get("SubStatus")
        status = event_data.get("Status")

        if event_id == 4624:
            event_type = EventType.ACCEPTED_LOGIN
        elif event_id == 4625:
            # 0xC0000064 indicates STATUS_NO_SUCH_USER
            if sub_status and sub_status.upper() == "0XC0000064":
                event_type = EventType.INVALID_USER
            else:
                event_type = EventType.FAILED_LOGIN
        else:
            return None

        username = event_data.get("TargetUserName", "")
        if not username:
            return None

        hostname = system.get("Computer", "")
        pid = int(system.get("Execution", {}).get("ProcessID", 0))
        logon_type = int(event_data.get("LogonType", 0))
        workstation_name = event_data.get("WorkstationName")

        return WindowsAuthEvent(
            timestamp=dt,
            hostname=hostname,
            process_id=pid,
            event_id=event_id,
            event_type=event_type,
            username=username,
            source_ip=ip_str,
            port=port,
            logon_type=logon_type,
            workstation_name=workstation_name if workstation_name != "-" else None,
            status=status,
            sub_status=sub_status,
            raw_event=event_dict,
        )
    except (ValidationError, ValueError, TypeError, KeyError):
        return None