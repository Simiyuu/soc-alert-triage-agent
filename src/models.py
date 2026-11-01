from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field, IPvAnyAddress


class EventType(str, Enum):
    FAILED_LOGIN = "FAILED_LOGIN"
    INVALID_USER = "INVALID_USER"
    ACCEPTED_LOGIN = "ACCEPTED_LOGIN"


class CriticalityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    MISSION_CRITICAL = "MISSION_CRITICAL"


class UserRole(str, Enum):
    STANDARD = "STANDARD"
    PRIVILEGED_ADMIN = "PRIVILEGED_ADMIN"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    EXECUTIVE_VIP = "EXECUTIVE_VIP"


class TriageVerdict(str, Enum):
    BENIGN_NOISE = "BENIGN_NOISE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUSPICIOUS_REVIEW = "SUSPICIOUS_REVIEW"
    CRITICAL_CONTAINMENT = "CRITICAL_CONTAINMENT"


class AssetContext(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    criticality: CriticalityLevel = CriticalityLevel.LOW
    business_unit: str = "General IT"
    is_crown_jewel: bool = False
    environment: str = "production"  # production, staging, development


class UserContext(BaseModel):
    username: str
    role: UserRole = UserRole.STANDARD
    department: str = "General"
    is_vip: bool = False
    approved_source_subnets: List[str] = Field(default_factory=list)


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


class TriageAssessment(BaseModel):
    assessment_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    risk_score: float = Field(ge=0.0, le=100.0)
    verdict: TriageVerdict
    risk_factors: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    asset_context: Optional[AssetContext] = None
    user_context: Optional[UserContext] = None
    recommended_actions: List[str] = Field(default_factory=list)
    requires_containment: bool = False
    