"""
Nmap Scanner Adapter
Integrates existing nmap scanning with unified architecture
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


class NmapScannerAdapter(BaseScannerAdapter):
    """Adapter for existing Nmap network scanner"""

    @property
    def legacy_scanner_class(self):
        from tools.views import NmapScanLaunch
        return NmapScanLaunch

    @property
    def legacy_parser_class(self):
        from scanners.scanner_parser.network_scanner import nmap_parser
        return nmap_parser

    def initialize(self) -> bool:
        """Initialize Nmap scanner"""
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
            
            logger.info(f"Nmap adapter initialized for {self.config.target}")
            return True
        except Exception as e:
            logger.exception(f"Nmap initialization failed: {e}")
            return False

    def execute_scan(self) -> ScanResult:
        """Execute Nmap scan using existing plugin"""
        if not self._legacy_scanner:
            self.result.scan_status = ScanStatus.FAILED
            self.result.failure_reason = "Scanner not initialized"
            return self.result
        
        try:
            self.result.scan_status = ScanStatus.RUNNING
            self.result.started_at = datetime.now()
            
            # Run Nmap scan
            # The existing NmapScanLaunch class has post method
            from django.http import HttpRequest
            import json
            
            request = HttpRequest()
            request.method = 'POST'
            request._body = json.dumps({
                'target': self.config.target,
                'scan_type': self.config.options.get('scan_type', 'basic'),
                'ports': self.config.options.get('ports', '1-1000'),
            }).encode('utf-8')
            request.META = {}
            
            response = self._legacy_scanner.post(request)
            
            # Check response
            if hasattr(response, 'status_code') and response.status_code != 200:
                raise RuntimeError("Nmap scan failed")
            
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
            
            logger.info(f"Nmap scan completed: {self.result.total_vulns} vulnerabilities found")
            return self.result
            
        except Exception as e:
            logger.exception(f"Nmap scan failed: {e}")
            self.result.scan_status = ScanStatus.FAILED
            self.result.failure_reason = str(e)
            self.result.completed_at = datetime.now()
            return self.result

    def get_results(self) -> List[Dict[str, Any]]:
        """Get scan results using existing XML parser"""
        if not self._legacy_scanner:
            return []
        
        try:
            from scanners.scanner_parser.network_scanner import nmap_parser
            import os
            import glob
            
            # Look for Nmap XML report
            report_dir = os.path.join(os.getcwd(), "nmap_reports")
            if not os.path.exists(report_dir):
                return []
            
            # Find the latest report for this target
            target_safe = self.config.target.replace(".", "_").replace("/", "_")
            report_files = glob.glob(os.path.join(report_dir, f"*{target_safe}*.xml"))
            
            if not report_files:
                return []
            
            latest_report = max(report_files, key=os.path.getctime)
            
            # Use existing parser
            with open(latest_report, 'r') as f:
                content = f.read()
            
            import io
            file_obj = io.StringIO(content)
            
            parsed_results = nmap_parser.xml_parser(
                file_obj, 
                project_id=self.config.project_id,
                scan_id=self.config.scan_id,
                username=None
            )
            
            return parsed_results if parsed_results else []
            
        except Exception as e:
            logger.exception(f"Failed to get Nmap results: {e}")
            return []

    def cleanup(self) -> bool:
        """Cleanup Nmap resources"""
        try:
            return True
        except Exception as e:
            logger.error(f"Nmap cleanup failed: {e}")
            return False