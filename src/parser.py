import re
from datetime import datetime
from typing import List, Optional
from src.models import EventType, SSHAuthEvent

SSH_FAILED_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"Failed password for (?P<invalid_flag>invalid user\s+)?(?P<username>\S+)\s+from\s+"
    r"(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)"
)

SSH_INVALID_USER_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"Invalid user (?P<username>\S+)\s+from\s+"
    r"(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)"
)

SSH_ACCEPTED_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"Accepted password for (?P<username>\S+)\s+from\s+"
    r"(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)"
)


def parse_syslog_timestamp(month: str, day: str, time_str: str, year: int = 2026) -> datetime:
    """Standard syslog formats omit the year. We reconstruct a valid datetime object."""
    date_str = f"{year} {month} {day.strip()} {time_str}"
    return datetime.strptime(date_str, "%Y %b %d %H:%M:%S")


def parse_line(line: str) -> Optional[SSHAuthEvent]:
    line = line.replace("\xa0", " ").lstrip("\ufeff").strip()
    if not line:
        return None

    match = SSH_FAILED_PATTERN.search(line)
    if match:
        data = match.groupdict()
        event_type = EventType.INVALID_USER if data.get("invalid_flag") else EventType.FAILED_LOGIN
        return SSHAuthEvent(
            timestamp=parse_syslog_timestamp(data["month"], data["day"], data["time"]),
            hostname=data["hostname"],
            process_id=int(data["pid"]),
            event_type=event_type,
            username=data["username"],
            source_ip=data["src_ip"],
            port=int(data["port"]),
            raw_log=line,
        )

    match = SSH_INVALID_USER_PATTERN.search(line)
    if match:
        data = match.groupdict()
        return SSHAuthEvent(
            timestamp=parse_syslog_timestamp(data["month"], data["day"], data["time"]),
            hostname=data["hostname"],
            process_id=int(data["pid"]),
            event_type=EventType.INVALID_USER,
            username=data["username"],
            source_ip=data["src_ip"],
            port=int(data["port"]),
            raw_log=line,
        )

    match = SSH_ACCEPTED_PATTERN.search(line)
    if match:
        data = match.groupdict()
        return SSHAuthEvent(
            timestamp=parse_syslog_timestamp(data["month"], data["day"], data["time"]),
            hostname=data["hostname"],
            process_id=int(data["pid"]),
            event_type=EventType.ACCEPTED_LOGIN,
            username=data["username"],
            source_ip=data["src_ip"],
            port=int(data["port"]),
            raw_log=line,
        )

    return None


def parse_log_file(file_path: str) -> List[SSHAuthEvent]:
    events = []
    with open(file_path, "r", encoding="utf-8-sig") as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                events.append(parsed)
    return events