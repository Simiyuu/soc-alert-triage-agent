from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, IPvAnyAddress


class EventType(str, Enum):
    FAILED_LOGIN = "FAILED_LOGIN"
    INVALID_USER = "INVALID_USER"
    ACCEPTED_LOGIN = "ACCEPTED_LOGIN"


class SSHAuthEvent(BaseModel):
    timestamp: datetime
    hostname: str
    process_id: int
    event_type: EventType
    username: str
    source_ip: IPvAnyAddress
    port: int
    raw_log: str = Field(..., description="Original raw syslog line for auditability")