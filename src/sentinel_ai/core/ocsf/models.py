"""OCSF (Open Cybersecurity Schema Framework) Event Models.

Implements canonical OCSF schema mappings per ADR-001.
"""

from enum import IntEnum

from pydantic import BaseModel, ConfigDict, Field


class SeverityID(IntEnum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


class CategoryUID(IntEnum):
    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IDENTITY_MANAGEMENT = 3
    NETWORK_ACTIVITY = 4


class ClassUID(IntEnum):
    PROCESS_ACTIVITY = 1007
    FINDING = 2001
    AUTHENTICATION = 3002
    NETWORK_ACTIVITY = 4001


class OCSFMetadata(BaseModel):
    """Metadata container for OCSF events."""

    version: str = "1.1.0"
    product_name: str
    vendor_name: str
    processed_time: int | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class OCSFBaseEvent(BaseModel):
    """Canonical base OCSF event schema."""

    model_config = ConfigDict(extra="ignore")

    activity_id: int
    category_uid: CategoryUID
    class_uid: ClassUID
    severity_id: SeverityID = SeverityID.INFORMATIONAL
    time: int = Field(description="Epoch timestamp in seconds or milliseconds")
    metadata: OCSFMetadata
    message: str | None = None
    raw_data: str | None = None

    def get_event_id(self) -> str:
        """Generate a deterministic event fingerprint for deduplication."""
        return f"{self.class_uid}:{self.time}:{self.metadata.vendor_name}:{self.activity_id}"


class AuthenticationEvent(OCSFBaseEvent):
    """OCSF Class 3002: Identity Authentication Event."""

    category_uid: CategoryUID = CategoryUID.IDENTITY_MANAGEMENT
    class_uid: ClassUID = ClassUID.AUTHENTICATION
    user_name: str
    src_endpoint_ip: str | None = None
    is_success: bool = True
    status_code: str | None = None


class NetworkActivityEvent(OCSFBaseEvent):
    """OCSF Class 4001: Network Activity Event."""

    category_uid: CategoryUID = CategoryUID.NETWORK_ACTIVITY
    class_uid: ClassUID = ClassUID.NETWORK_ACTIVITY
    src_endpoint_ip: str
    dst_endpoint_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "TCP"
    bytes_in: int | None = None
    bytes_out: int | None = None


class ProcessActivityEvent(OCSFBaseEvent):
    """OCSF Class 1007: Process Activity Event."""

    category_uid: CategoryUID = CategoryUID.SYSTEM_ACTIVITY
    class_uid: ClassUID = ClassUID.PROCESS_ACTIVITY
    process_name: str
    process_path: str | None = None
    process_pid: int | None = None
    parent_process_name: str | None = None
    command_line: str | None = None


class FindingEvent(OCSFBaseEvent):
    """OCSF Class 2001: Security Finding / Anomaly Event."""

    category_uid: CategoryUID = CategoryUID.FINDINGS
    class_uid: ClassUID = ClassUID.FINDING
    title: str
    analytic_name: str
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    remediation_guidance: str | None = None
