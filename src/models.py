from datetime import datetime
from enum import Enum
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


class AggregatedAlert(BaseModel):
    source_ip: str
    total_failures: int
    targeted_usernames: list[str]
    first_seen: datetime
    last_seen: datetime
    duration_seconds: float
    is_brute_force: bool
    summary: str

class IPReputation(BaseModel):
    ip: str
    is_private: bool
    reputation_score: int = Field(
        ..., description="Risk score from 0 (clean) to 100 (confirmed malicious)"
    )
    country: str
    asn_org: str
    threat_tags: list[str]


class EnrichedAlert(BaseModel):
    alert: AggregatedAlert
    reputation: IPReputation