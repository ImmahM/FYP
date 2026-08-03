from abc import ABC, abstractmethod
from typing import Dict, Any, List, BinaryIO, Optional
from dataclasses import dataclass, field
from enum import Enum


class ParseFormat(str, Enum):
    XML = "xml"
    JSON = "json"
    HTML = "html"
    CSV = "csv"
    TXT = "txt"
    PDF = "pdf"


@dataclass
class ParseResult:
    vulnerabilities: List["VulnerabilityResult"] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class ResultParserBase(ABC):
    """Abstract base class for result parsers"""

    def __init__(self, scan_type: str):
        self.scan_type = scan_type
        self.supported_formats: List[ParseFormat] = []

    @abstractmethod
    def can_parse(self, file_data: BinaryIO, file_format: str) -> bool:
        """Check if parser can handle the given file format"""
        pass

    @abstractmethod
    def parse(self, file_data: BinaryIO) -> ParseResult:
        """Parse raw scan results into structured data"""
        pass

    @abstractmethod
    def save_to_database(self, parsed_data: ParseResult, scan_id: str) -> bool:
        """Save parsed results to database
        
        Args:
            parsed_data: Parsed vulnerabilities
            scan_id: Associated scan ID
            
        Returns:
            bool: True if save successful
        """
        pass

    def get_format(self) -> str:
        """Get primary supported format"""
        return self.supported_formats[0].value if self.supported_formats else "unknown"