from typing import Dict, Type, Optional, List, Any
from threading import Lock

from .scanner_base import ScannerBase, ScanConfig, ScanType
from .parser_base import ResultParserBase, ParseFormat
from .result_models import VulnerabilityResult


class ScannerRegistry:
    """Central registry for all scanner and parser plugins"""
    
    _scanners: Dict[str, Type[ScannerBase]] = {}
    _parsers: Dict[str, List[Type[ResultParserBase]]] = {}  # scan_type -> list of parsers
    _lock = Lock()

    @classmethod
    def register_scanner(cls, name: str, scanner_class: Type[ScannerBase]) -> None:
        """Register a scanner plugin
        
        Args:
            name: Unique scanner name (e.g., 'zap', 'burp', 'nikto')
            scanner_class: Scanner class inheriting from ScannerBase
        """
        with cls._lock:
            if not issubclass(scanner_class, ScannerBase):
                raise TypeError(f"{scanner_class} must inherit from ScannerBase")
            cls._scanners[name.lower()] = scanner_class

    @classmethod
    def register_parser(cls, scan_type: str, parser_class: Type[ResultParserBase]) -> None:
        """Register a parser plugin
        
        Args:
            scan_type: Type of scan (web, network, static, cloud, compliance)
            parser_class: Parser class inheriting from ResultParserBase
        """
        with cls._lock:
            if not issubclass(parser_class, ResultParserBase):
                raise TypeError(f"{parser_class} must inherit from ResultParserBase")
            if scan_type not in cls._parsers:
                cls._parsers[scan_type] = []
            if parser_class not in cls._parsers[scan_type]:
                cls._parsers[scan_type].append(parser_class)

    @classmethod
    def get_scanner(cls, name: str) -> Optional[Type[ScannerBase]]:
        """Get scanner class by name"""
        with cls._lock:
            return cls._scanners.get(name.lower())

    @classmethod
    def get_scanner_instance(cls, name: str, config: ScanConfig) -> Optional[ScannerBase]:
        """Get scanner instance by name"""
        scanner_class = cls.get_scanner(name)
        if scanner_class:
            return scanner_class(config)
        return None

    @classmethod
    def get_parsers_for_scan_type(cls, scan_type: str) -> List[Type[ResultParserBase]]:
        """Get all parsers for a scan type"""
        with cls._lock:
            return cls._parsers.get(scan_type, [])

    @classmethod
    def get_parser_for_format(cls, scan_type: str, file_format: str) -> Optional[Type[ResultParserBase]]:
        """Get parser that supports the given file format"""
        with cls._lock:
            parsers = cls._parsers.get(scan_type, [])
            for parser_class in parsers:
                if file_format.lower() in parser_class().get_supported_formats():
                    return parser_class
        return None

    @classmethod
    def list_scanners(cls) -> List[str]:
        """List all registered scanner names"""
        with cls._lock:
            return list(cls._scanners.keys())

    @classmethod
    def list_parsers(cls, scan_type: Optional[str] = None) -> Dict[str, List[str]]:
        """List all registered parsers"""
        with cls._lock:
            if scan_type:
                return {scan_type: [p.__name__ for p in cls._parsers.get(scan_type, [])]}
            return {st: [p.__name__ for p in parsers] for st, parsers in cls._parsers.items()}

    @classmethod
    def clear(cls) -> None:
        """Clear registry (for testing)"""
        with cls._lock:
            cls._scanners.clear()
            cls._parsers.clear()


class ResultMerger:
    """Handle duplicate detection and merging across scanner types"""

    @staticmethod
    def detect_duplicate(result: VulnerabilityResult, existing: List[VulnerabilityResult]) -> Optional[VulnerabilityResult]:
        """Check if vulnerability already exists in results"""
        for vuln in existing:
            if vuln.dup_hash == result.dup_hash:
                return vuln
        return None

    @staticmethod
    def merge_similar_findings(results: List[VulnerabilityResult]) -> List[VulnerabilityResult]:
        """Combine similar findings from multiple scans"""
        if not results:
            return []

        # Group by dup_hash
        grouped: Dict[str, List[VulnerabilityResult]] = {}
        for vuln in results:
            if vuln.dup_hash not in grouped:
                grouped[vuln.dup_hash] = []
            grouped[vuln.dup_hash].append(vuln)

        # Merge each group
        merged = []
        for dup_hash, vulns in grouped.items():
            if len(vulns) == 1:
                merged.append(vulns[0])
            else:
                # Merge all in group
                base = vulns[0]
                for other in vulns[1:]:
                    base = base.merge_with(other)
                merged.append(base)

        return merged

    @staticmethod
    def deduplicate(results: List[VulnerabilityResult]) -> List[VulnerabilityResult]:
        """Remove duplicates based on dup_hash"""
        seen: Dict[str, VulnerabilityResult] = {}
        for vuln in results:
            if vuln.dup_hash not in seen:
                seen[vuln.dup_hash] = vuln
        return list(seen.values())