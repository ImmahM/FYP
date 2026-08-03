from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging


logger = logging.getLogger(__name__)


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, Enum):
    WEB = "web"
    NETWORK = "network"
    STATIC = "static"
    CLOUD = "cloud"
    COMPLIANCE = "compliance"
    CONTAINER = "container"
    SAST = "sast"
    DAST = "dast"


@dataclass
class ScanConfig:
    """Scan configuration shared across all scanner types"""
    scan_id: str
    scan_type: ScanType
    scanner_name: str
    target: str
    organization_id: int
    project_id: Optional[int] = None
    created_by_id: Optional[int] = None
    options: Dict[str, Any] = field(default_factory=dict)
    credentials: Dict[str, Any] = field(default_factory=dict)
    schedule_config: Optional[Dict[str, Any]] = None


@dataclass
class ScanResult:
    """Standardized scan result"""
    scan_id: str
    scan_status: ScanStatus = ScanStatus.PENDING
    total_vulns: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    failure_reason: Optional[str] = None
    raw_output: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ScannerBase(ABC):
    """Abstract base class for all scanners"""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.result = ScanResult(
            scan_id=config.scan_id,
            scan_status=ScanStatus.PENDING,
        )
        self._initialized = False
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize scanner with configuration
        
        Returns:
            bool: True if initialization successful
        """
        pass

    @abstractmethod
    def execute_scan(self) -> ScanResult:
        """Execute the actual scan
        
        Returns:
            ScanResult: Results of the scan execution
        """
        pass

    @abstractmethod
    def get_results(self) -> List[Dict[str, Any]]:
        """Retrieve raw scan results
        
        Returns:
            List of raw vulnerability findings
        """
        pass

    @abstractmethod
    def cleanup(self) -> bool:
        """Cleanup after scan completion
        
        Returns:
            bool: True if cleanup successful
        """
        pass

    def _validate_config(self) -> bool:
        """Common configuration validation"""
        if not self.config.target:
            self._logger.error("Target is required")
            return False
        if not self.config.organization_id:
            self._logger.error("Organization ID is required")
            return False
        return True

    def run(self) -> ScanResult:
        """Execute full scan lifecycle"""
        self._logger.info(f"Starting scan {self.config.scan_id} for target {self.config.target}")
        self.result.started_at = datetime.now()
        self.result.scan_status = ScanStatus.RUNNING

        try:
            if not self._validate_config():
                raise ValueError("Invalid scan configuration")

            if not self.initialize():
                raise RuntimeError("Scanner initialization failed")

            self._initialized = True
            self.result = self.execute_scan()
            self.result.scan_status = ScanStatus.COMPLETED
            self._logger.info(f"Scan {self.config.scan_id} completed successfully")

        except Exception as e:
            self._logger.exception(f"Scan {self.config.scan_id} failed: {e}")
            self.result.scan_status = ScanStatus.FAILED
            self.result.failure_reason = str(e)

        finally:
            self.result.completed_at = datetime.now()
            self.cleanup()

        return self.result

    def get_scan_summary(self) -> Dict[str, Any]:
        """Get scan execution summary"""
        return {
            "scan_id": self.config.scan_id,
            "scan_type": self.config.scan_type.value,
            "scanner_name": self.config.scanner_name,
            "target": self.config.target,
            "status": self.result.scan_status.value,
            "total_vulns": self.result.total_vulns,
            "severity_counts": {k: v for k, v in self.result.severity_counts.items()},
            "started_at": self.result.started_at.isoformat() if self.result.started_at else None,
            "completed_at": self.result.completed_at.isoformat() if self.result.completed_at else None,
            "failure_reason": self.result.failure_reason,
        }