from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, IPvAnyAddress
import uuid

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
    port: int = Field(ge=1, le=65535)
    raw_log: str


class WindowsAuthEvent(BaseModel):
    timestamp: datetime
    hostname: str
    process_id: int
    event_id: int
    event_type: EventType
    username: str
    source_ip: IPvAnyAddress
    port: int = Field(ge=1, le=65535)
    logon_type: int
    workstation_name: Optional[str] = None
    status: Optional[str] = None
    sub_status: Optional[str] = None
    raw_event: Optional[Dict[str, Any]] = None

class UnifiedAuthRecord(BaseModel):
    timestamp: datetime
    hostname: str
    service: str  # e.g. "sshd", "windows_security"
    event_type: EventType
    username: str
    source_ip: IPvAnyAddress
    port: int = Field(ge=1, le=65535)
    logon_type: Optional[int] = None
    raw_reference: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SecurityAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rule_id: str
    rule_name: str
    mitre_technique: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    source_ip: str
    target_users: List[str]
    event_count: int
    first_seen: datetime
    last_seen: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)