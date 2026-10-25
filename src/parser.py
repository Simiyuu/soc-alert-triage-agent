import re
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import ValidationError
from src.models import EventType, SSHAuthEvent

# Unified header pattern supporting RFC 5424 (ISO-8601) and RFC 3164 (BSD syslog)
HEADER_PATTERN = (
    r"^(?:(?P<iso_ts>\d{4}-\d{2}-\d{2}T[^\s]+)|"
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}))\s+"
    r"(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
)

# Resilient message patterns with non-greedy username matching
SSH_FAILED_PATTERN = re.compile(
    HEADER_PATTERN + r"Failed password for (?P<invalid_flag>invalid user\s+)?(?P<username>.+?)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)"
)

SSH_INVALID_USER_PATTERN = re.compile(
    HEADER_PATTERN + r"Invalid user (?P<username>.+?)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)"
)

SSH_ACCEPTED_PATTERN = re.compile(
    HEADER_PATTERN + r"Accepted (?:password|publickey|keyboard-interactive\S*)\s+for (?P<username>.+?)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)"
)


def parse_timestamp(data: dict) -> datetime:
    """Parses ISO-8601 or BSD syslog timestamps and ensures UTC-awareness."""
    if data.get("iso_ts"):
        dt = datetime.fromisoformat(data["iso_ts"])
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    current_year = datetime.now(timezone.utc).year
    dt = datetime.strptime(
        f"{current_year} {data['month']} {data['day']} {data['time']}",
        "%Y %b %d %H:%M:%S"
    )
    return dt.replace(tzinfo=timezone.utc)


def parse_line(line: str) -> Optional[SSHAuthEvent]:
    """Defensively parses a single syslog line into a validated SSHAuthEvent."""
    line = line.replace("\xa0", " ").lstrip("\ufeff").strip()
    if not line:
        return None

    data = None
    event_type = None

    match_failed = SSH_FAILED_PATTERN.search(line)
    if match_failed:
        data = match_failed.groupdict()
        event_type = EventType.INVALID_USER if data.get("invalid_flag") else EventType.FAILED_LOGIN
    else:
        match_invalid = SSH_INVALID_USER_PATTERN.search(line)
        if match_invalid:
            data = match_invalid.groupdict()
            event_type = EventType.INVALID_USER
        else:
            match_accepted = SSH_ACCEPTED_PATTERN.search(line)
            if match_accepted:
                data = match_accepted.groupdict()
                event_type = EventType.ACCEPTED_LOGIN

    if not data or not event_type:
        return None

    try:
        port = int(data["port"])
        if not (1 <= port <= 65535):
            return None

        return SSHAuthEvent(
            timestamp=parse_timestamp(data),
            hostname=data["hostname"],
            process_id=int(data["pid"]),
            event_type=event_type,
            username=data["username"],
            source_ip=data["src_ip"],
            port=port,
            raw_log=line,
        )
    except (ValidationError, ValueError):
        return None


def parse_file(file_path: str) -> List[SSHAuthEvent]:
    """Parses an entire log file, discarding malformed or non-auth lines."""
    events: List[SSHAuthEvent] = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events