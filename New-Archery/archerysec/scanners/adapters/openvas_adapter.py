"""
OpenVAS Scanner Adapter
Integrates existing OpenVAS scanner with unified architecture
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


class OpenVASScannerAdapter(BaseScannerAdapter):
    """Adapter for existing OpenVAS network scanner"""

    @property
    def legacy_scanner_class(self):
        from scanners.scanner_plugin.network_scanner import openvas_plugin
        return openvas_plugin.OpenVAS

    @property
    def legacy_parser_class(self):
        from scanners.scanner_parser.network_scanner import OpenVas_Parser
        return OpenVas_Parser

    def initialize(self) -> bool:
        """Initialize OpenVAS scanner"""
        try:
            # Load OpenVAS settings from database
            from archerysettings.models import OpenVASSettingsDb
            openvas_settings = OpenVASSettingsDb.objects.first()
            
            if not openvas_settings:
                logger.error("OpenVAS settings not configured in database")
                return False
            
            self._openvas_host = openvas_settings.openvas_host or "0.0.0.0"
            self._openvas_port = openvas_settings.openvas_port or "9390"
            self._openvas_user = openvas_settings.openvas_user or "admin"
            self._openvas_password = openvas_settings.openvas_password or "admin"
            
            # Initialize legacy scanner
            self._legacy_scanner = self.legacy_scanner_class(
                host=self._openvas_host,
                port=self._openvas_port,
                username=self._openvas_user,
                password=self._openvas_password
            )
            
            # Store scan config for parser
            self._scan_config = {
                'target': self.config.target,
                'project_id': self.config.project_id,
                'organization_id': self.config.organization_id,
                'created_by_id': self.config.created_by_id,
            }
            
            logger.info(f"OpenVAS adapter initialized for {self.config.target}")
            return True
        except Exception as e:
            logger.exception(f"OpenVAS initialization failed: {e}")
            return False

    def execute_scan(self) -> ScanResult:
        """Execute OpenVAS scan using existing plugin"""
        if not self._legacy_scanner:
            self.result.scan_status = ScanStatus.FAILED
            self.result.failure_reason = "Scanner not initialized"
            return self.result
        
        try:
            self.result.scan_status = ScanStatus.RUNNING
            self.result.started_at = datetime.now()
            
            # Run OpenVAS scan
            scan_result = self._legacy_scanner.start_scan(
                target=self.config.target,
                scan_config=self.config.options.get('scan_config', 'Full and fast'),
            )
            
            if scan_result is False:
                raise RuntimeError("OpenVAS scan failed")
            
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
            
            logger.info(f"OpenVAS scan completed: {self.result.total_vulns} vulnerabilities found")
            return self.result
            
        except Exception as e:
            logger.exception(f"OpenVAS scan failed: {e}")
            self.result.scan_status = ScanStatus.FAILED
            self.result.failure_reason = str(e)
            self.result.completed_at = datetime.now()
            return self.result

    def get_results(self) -> List[Dict[str, Any]]:
        """Get scan results using existing XML parser"""
        if not self._legacy_scanner:
            return []
        
        try:
            from scanners.scanner_parser.network_scanner import OpenVas_Parser
            import os
            import glob
            
            # Look for OpenVAS XML report
            report_dir = os.path.join(os.getcwd(), "openvas_reports")
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
            
            parsed_results = OpenVas_Parser.xml_parser(
                file_obj, 
                project_id=self.config.project_id,
                scan_id=self.config.scan_id,
                username=None
            )
            
            return parsed_results if parsed_results else []
            
        except Exception as e:
            logger.exception(f"Failed to get OpenVAS results: {e}")
            return []

    def cleanup(self) -> bool:
        """Cleanup OpenVAS resources"""
        try:
            if self._legacy_scanner:
                self._legacy_scanner.logout()
            return True
        except Exception as e:
            logger.error(f"OpenVAS cleanup failed: {e}")
            return False