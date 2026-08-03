"""
Abstract base classes for scanner and parser adapters
These wrap existing ArcherySec scanner plugins with the new unified interface
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, BinaryIO, Optional
from dataclasses import dataclass, field
from datetime import datetime

from scanners.base import (
    ScannerBase, ResultParserBase, ScanConfig, ScanResult, 
    ScanStatus, ScanType, SeverityLevel, VulnerabilityResult
)


@dataclass
class AdapterConfig:
    """Extended config for adapters"""
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


class BaseScannerAdapter(ScannerBase):
    """Base adapter class for wrapping existing scanner plugins"""
    
    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self._legacy_scanner = None
        self._parser = None
        
    @property
    @abstractmethod
    def legacy_scanner_class(self):
        """Return the legacy scanner class to wrap"""
        pass
    
    @property
    @abstractmethod
    def legacy_parser_class(self):
        """Return the legacy parser class to wrap"""
        pass

    def initialize(self) -> bool:
        """Initialize the legacy scanner"""
        try:
            self._legacy_scanner = self.legacy_scanner_class(
                target_url=self.config.target,
                project_id=self.config.project_id,
                rescan_id=None,
                rescan=None,
                request=None
            )
            return True
        except Exception as e:
            self._logger.error(f"{self.__class__.__name__} initialization failed: {e}")
            return False

    @abstractmethod
    def execute_scan(self) -> ScanResult:
        """Execute the scan using legacy scanner"""
        pass

    @abstractmethod
    def get_results(self) -> List[Dict[str, Any]]:
        """Get results using legacy parser"""
        pass

    def cleanup(self) -> bool:
        """Cleanup legacy scanner resources"""
        try:
            if self._legacy_scanner and hasattr(self._legacy_scanner, 'zap_shutdown'):
                self._legacy_scanner.zap_shutdown()
            return True
        except Exception as e:
            self._logger.error(f"Cleanup failed: {e}")
            return False


class BaseParserAdapter(ResultParserBase):
    """Base parser adapter for wrapping existing parsers"""
    
    def __init__(self, scan_type: str):
        super().__init__(scan_type)
        self._legacy_parser = None
        
    @property
    @abstractmethod
    def supported_formats(self) -> List[str]:
        """Return supported file formats"""
        pass

    def can_parse(self, file_data: BinaryIO, file_format: str) -> bool:
        """Check if parser can handle the format"""
        return file_format.lower() in [f.lower() for f in self.supported_formats]

    @abstractmethod
    def parse(self, file_data: BinaryIO) -> List[VulnerabilityResult]:
        """Parse using legacy parser"""
        pass

    @abstractmethod
    def save_to_database(self, parsed_data: List[VulnerabilityResult], scan_id: str) -> bool:
        """Save parsed results to database"""
        pass