from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum
import uuid
import hashlib


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def weight(self) -> int:
        """Numeric weight for severity comparison"""
        weights = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1,
            SeverityLevel.UNKNOWN: 0,
        }
        return weights.get(self, 0)

    def __lt__(self, other):
        if isinstance(other, SeverityLevel):
            return self.weight < other.weight
        return NotImplemented

    def __le__(self, other):
        if isinstance(other, SeverityLevel):
            return self.weight <= other.weight
        return NotImplemented

    def __gt__(self, other):
        if isinstance(other, SeverityLevel):
            return self.weight > other.weight
        return NotImplemented

    def __ge__(self, other):
        if isinstance(other, SeverityLevel):
            return self.weight >= other.weight
        return NotImplemented


class ScanType(str, Enum):
    WEB = "web"
    NETWORK = "network"
    STATIC = "static"
    CLOUD = "cloud"
    COMPLIANCE = "compliance"
    CONTAINER = "container"
    SAST = "sast"
    DAST = "dast"


class VulnStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"
    IN_PROGRESS = "in_progress"


@dataclass
class VulnerabilityResult:
    """Unified vulnerability data structure across all scanner types"""
    
    # Core identification
    vuln_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""
    scan_type: ScanType = ScanType.WEB
    scanner_name: str = ""
    
    # Vulnerability details
    title: str = ""
    description: str = ""
    solution: str = ""
    severity: SeverityLevel = SeverityLevel.UNKNOWN
    
    # Location context
    url: str = ""
    host: str = ""
    port: str = ""
    path: str = ""
    parameter: str = ""
    method: str = ""
    
    # Identification & classification
    cve_id: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    
    # Evidence
    evidence: str = ""
    request: str = ""
    response: str = ""
    payload: str = ""
    
    # Tracking
    dup_hash: str = ""
    false_positive: str = "No"
    vuln_status: VulnStatus = VulnStatus.OPEN
    
    # References
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    # Metadata
    organization_id: Optional[int] = None
    project_id: Optional[int] = None
    created_by_id: Optional[int] = None
    date_time: datetime = field(default_factory=datetime.now)
    additional_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.dup_hash:
            self.dup_hash = self._generate_dup_hash()
        if isinstance(self.severity, str):
            self.severity = SeverityLevel(self.severity.lower())
        if isinstance(self.vuln_status, str):
            self.vuln_status = VulnStatus(self.vuln_status.lower())
        if isinstance(self.scan_type, str):
            self.scan_type = ScanType(self.scan_type.lower())

    def _generate_dup_hash(self) -> str:
        """Generate consistent deduplication hash"""
        key_parts = [
            self.scan_type.value,
            self.scanner_name,
            self.title,
            self.host,
            self.port,
            self.path,
            self.parameter,
            self.cve_id,
        ]
        key_string = "|".join(str(p) for p in key_parts if p)
        return hashlib.sha256(key_string.encode()).hexdigest()[:32]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "vuln_id": self.vuln_id,
            "scan_id": self.scan_id,
            "scan_type": self.scan_type.value,
            "scanner_name": self.scanner_name,
            "title": self.title,
            "description": self.description,
            "solution": self.solution,
            "severity": self.severity.value,
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "parameter": self.parameter,
            "method": self.method,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "payload": self.payload,
            "dup_hash": self.dup_hash,
            "false_positive": self.false_positive,
            "vuln_status": self.vuln_status.value,
            "references": self.references,
            "tags": self.tags,
            "organization_id": self.organization_id,
            "project_id": self.project_id,
            "created_by_id": self.created_by_id,
            "date_time": self.date_time.isoformat() if self.date_time else None,
            "additional_metadata": self.additional_metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VulnerabilityResult":
        """Create from dictionary"""
        return cls(**data)

    def merge_with(self, other: "VulnerabilityResult") -> "VulnerabilityResult":
        """Merge with another vulnerability finding (for deduplication)"""
        merged = VulnerabilityResult(
            vuln_id=self.vuln_id,
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            scanner_name=f"{self.scanner_name}, {other.scanner_name}",
            title=self.title,
            description=self.description or other.description,
            solution=self.solution or other.solution,
            severity=max(self.severity, other.severity),
            url=self.url or other.url,
            host=self.host or other.host,
            port=self.port or other.port,
            path=self.path or other.path,
            parameter=self.parameter or other.parameter,
            method=self.method or other.method,
            cve_id=self.cve_id or other.cve_id,
            cwe_id=self.cwe_id or other.cwe_id,
            owasp_category=self.owasp_category or other.owasp_category,
            cvss_score=max(filter(None, [self.cvss_score, other.cvss_score]), default=None),
            cvss_vector=self.cvss_vector or other.cvss_vector,
            evidence=self.evidence or other.evidence,
            request=self.request or other.request,
            response=self.response or other.response,
            payload=self.payload or other.payload,
            dup_hash=self.dup_hash,
            false_positive="Yes" if self.false_positive == "Yes" or other.false_positive == "Yes" else "No",
            vuln_status=self.vuln_status,
            references=list(set(self.references + other.references)),
            tags=list(set(self.tags + other.tags)),
            organization_id=self.organization_id or other.organization_id,
            project_id=self.project_id or other.project_id,
            created_by_id=self.created_by_id or other.created_by_id,
            date_time=min(filter(None, [self.date_time, other.date_time]), default=datetime.now()),
            additional_metadata={**self.additional_metadata, **other.additional_metadata},
        )
        merged.dup_hash = merged._generate_dup_hash()
        return merged