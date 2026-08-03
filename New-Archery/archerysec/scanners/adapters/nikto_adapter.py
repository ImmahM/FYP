"""
Nikto Scanner Adapter
Integrates existing nikto_plugin.Nikto with unified architecture
"""
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime

from scanners.base import (
    ScanConfig, ScanResult, ScanStatus, ScanType, 
    SeverityLevel, VulnerabilityResult
)
from scanners.adapters.abstracts import BaseScannerAdapter


logger = logging.getLogger(__name__)


class NiktoScannerAdapter(BaseScannerAdapter):
    """Adapter for existing Nikto scanner plugin"""

    @property
    def legacy_scanner_class(self):
        from scanners.scanner_plugin.web_scanner import nikto_plugin
        return nikto_plugin.Nikto

    @property
    def legacy_parser_class(self):
        from scanners.scanner_parser.tools import nikto_htm_parser
        return nikto_htm_parser

    def initialize(self) -> bool:
        """Initialize Nikto scanner"""
        try:
            # Initialize legacy scanner
            self._legacy_scanner = self.legacy_scanner_class()
            
            # Store scan config for parser
            self._scan_config = {
                'target': self.config.target,
                'project_id': self.config.project_id,
                'organization_id': self.config.organization_id,
                'created_by_id': self.config.created_by_id,
            }
            
            logger.info(f"Nikto adapter initialized for {self.config.target}")
            return True
        except Exception as e:
            logger.exception(f"Nikto initialization failed: {e}")
            return False

    def execute_scan(self) -> ScanResult:
        """Execute Nikto scan using existing plugin"""
        if not self._legacy_scanner:
            self.result.scan_status = ScanStatus.FAILED
            self.result.failure_reason = "Scanner not initialized"
            return self.result
        
        try:
            self.result.scan_status = ScanStatus.RUNNING
            self.result.started_at = datetime.now()
            
            # Run Nikto scan
            # The existing Nikto plugin has start_scan method
            scan_output = self._legacy_scanner.start_scan(self.config.target)
            
            if scan_output is False:
                raise RuntimeError("Nikto scan failed")
            
            self.result.scan_status = ScanStatus.COMPLETED
            self.result.completed_at = datetime.now()
            
            # Get results
            vulns = self.get_results()
            self.result.total_vulns = len(vulns)
            
            for vuln in vulns:
                severity = vuln.get('severity', SeverityLevel.INFO)
                if isinstance(severity, SeverityLevel):
                    self.result.severity_counts[severity] = \
                        self.result.severity_counts.get(severity, 0) + 1
            
            logger.info(f"Nikto scan completed: {self.result.total_vulns} vulnerabilities found")
            return self.result
            
        except Exception as e:
            logger.exception(f"Nikto scan failed: {e}")
            self.result.scan_status = ScanStatus.FAILED
            self.result.failure_reason = str(e)
            self.result.completed_at = datetime.now()
            return self.result

    def get_results(self) -> List[Dict[str, Any]]:
        """Get scan results using existing HTML parser"""
        if not self._legacy_scanner:
            return []
        
        try:
            # The existing Nikto plugin saves results to HTML file
            # Parse using existing parser
            from scanners.scanner_parser.tools import nikto_htm_parser
            import os
            import glob
            
            # Look for Nikto HTML report
            report_dir = os.path.join(os.getcwd(), "nikto_reports")
            if not os.path.exists(report_dir):
                return []
            
            # Find the latest report for this target
            target_safe = self.config.target.replace("://", "_").replace("/", "_").replace(":", "_")
            report_files = glob.glob(os.path.join(report_dir, f"*{target_safe}*.html"))
            
            if not report_files:
                return []
            
            latest_report = max(report_files, key=os.path.getctime)
            
            # Use existing parser
            with open(latest_report, 'r') as f:
                content = f.read()
            
            import io
            file_obj = io.StringIO(content)
            
            # The existing parser expects specific parameters
            parsed_results = nikto_htm_parser.htm_parser(
                file_obj, 
                project_id=self.config.project_id,
                scan_id=self.config.scan_id,
                username=None
            )
            
            return parsed_results if parsed_results else []
            
        except Exception as e:
            logger.exception(f"Failed to get Nikto results: {e}")
            return []

    def cleanup(self) -> bool:
        """Cleanup Nikto resources"""
        try:
            # Nikto scanner doesn't typically need explicit cleanup
            return True
        except Exception as e:
            logger.error(f"Nikto cleanup failed: {e}")
            return False