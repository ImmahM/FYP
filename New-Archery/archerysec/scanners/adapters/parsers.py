"""
Parser Adapters
Integrates existing parsers with unified ResultParserBase interface
"""
import os
import glob
import io
import logging
from typing import BinaryIO, List, Dict, Any

from scanners.base import (
    ResultParserBase, ParseFormat, ParseResult, VulnerabilityResult, 
    ScanType, SeverityLevel
)


logger = logging.getLogger(__name__)


class ZAPXMLParserAdapter(ResultParserBase):
    """Parser adapter for ZAP XML output"""

    def __init__(self):
        super().__init__(scan_type="web")
        self.supported_formats = [ParseFormat.XML, ParseFormat.HTML]

    def can_parse(self, file_data: BinaryIO, file_format: str) -> bool:
        """Check if this is a ZAP XML report"""
        if file_format.lower() not in ['xml', 'zap']:
            return False
        
        try:
            file_data.seek(0)
            content = file_data.read(1024).decode('utf-8', errors='ignore')
            file_data.seek(0)
            return 'OWASPZAPReport' in content or '<report>' in content
        except Exception:
            return False

    def parse(self, file_data: BinaryIO) -> ParseResult:
        """Parse ZAP XML report using existing parser"""
        parse_result = ParseResult()
        
        try:
            from scanners.scanner_parser.web_scanner import zap_xml_parser
            from django.http import HttpRequest
            
            file_data.seek(0)
            content = file_data.read().decode('utf-8', errors='ignore')
            file_data.seek(0)
            
            request = HttpRequest()
            request.META = {}
            request.user = None
            
            file_obj = io.StringIO(content)
            parsed = zap_xml_parser.xml_parser(
                request, file_obj, 
                project_id=None, scan_id=None, username=None
            )
            
            if parsed:
                for item in parsed:
                    vuln = VulnerabilityResult(
                        scan_type=ScanType.WEB,
                        scanner_name="ZAP",
                        title=item.get('name', ''),
                        description=item.get('description', ''),
                        solution=item.get('solution', ''),
                        severity=self._map_severity(item.get('severity', 'info')),
                        url=item.get('url', ''),
                        host=item.get('host', ''),
                        port=item.get('port', ''),
                        parameter=item.get('param', ''),
                        method=item.get('method', ''),
                        cwe_id=item.get('cwe', ''),
                        evidence=item.get('evidence', ''),
                        additional_metadata={
                            'zap_id': item.get('vuln_id', ''),
                            'false_positive': item.get('false_positive', 'No'),
                        }
                    )
                    parse_result.vulnerabilities.append(vuln)
                    
        except Exception as e:
            parse_result.errors.append(f"ZAP XML parse error: {str(e)}")
        
        return parse_result

    def save_to_database(self, parsed_data: ParseResult, scan_id: str) -> bool:
        """Save parsed results to database"""
        try:
            from webscanners.models import WebScanResultsDb, WebScansDb
            
            scan = WebScansDb.objects.filter(scan_id=scan_id).first()
            if not scan:
                return False
                
            for vuln in parsed_data.vulnerabilities:
                WebScanResultsDb.objects.create(
                    scan_id=vuln.scan_id or scan_id,
                    vuln_id=vuln.vuln_id,
                    name=vuln.title,
                    severity=vuln.severity.value if hasattr(vuln.severity, 'value') else vuln.severity,
                    description=vuln.description,
                    solution=vuln.solution,
                    url=vuln.url,
                    host=vuln.host,
                    port=vuln.port,
                    param=vuln.parameter,
                    method=vuln.method,
                    cwe_id=vuln.cwe_id,
                    evidence=vuln.evidence,
                    false_positive=vuln.false_positive,
                    vuln_status=vuln.vuln_status.value if hasattr(vuln.vuln_status, 'value') else vuln.vuln_status,
                    scanner_name=vuln.scanner_name,
                    dup_hash=vuln.dup_hash,
                    date_time=vuln.date_time,
                    additional_metadata=vuln.additional_metadata,
                )
            return True
        except Exception as e:
            logger.error(f"ZAP database save error: {str(e)}")
            return False

    def _map_severity(self, severity: str) -> SeverityLevel:
        mapping = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO,
            'informational': SeverityLevel.INFO,
        }
        return mapping.get(severity.lower(), SeverityLevel.INFO)


class NiktoHTMLParserAdapter(ResultParserBase):
    """Parser adapter for Nikto HTML output"""

    def __init__(self):
        super().__init__(scan_type="web")
        self.supported_formats = [ParseFormat.HTML]

    def can_parse(self, file_data: BinaryIO, file_format: str) -> bool:
        if file_format.lower() != 'html':
            return False
        
        try:
            file_data.seek(0)
            content = file_data.read(1024).decode('utf-8', errors='ignore')
            file_data.seek(0)
            return 'nikto' in content.lower() or 'Nikto' in content
        except Exception:
            return False

    def parse(self, file_data: BinaryIO) -> ParseResult:
        parse_result = ParseResult()
        
        try:
            from scanners.scanner_parser.tools import nikto_htm_parser
            from django.http import HttpRequest
            
            file_data.seek(0)
            content = file_data.read().decode('utf-8', errors='ignore')
            file_data.seek(0)
            
            request = HttpRequest()
            request.META = {}
            request.user = None
            
            file_obj = io.StringIO(content)
            parsed = nikto_htm_parser.htm_parser(
                file_obj, 
                project_id=None, scan_id=None, username=None
            )
            
            if parsed:
                for item in parsed:
                    vuln = VulnerabilityResult(
                        scan_type=ScanType.WEB,
                        scanner_name="Nikto",
                        title=item.get('name', ''),
                        description=item.get('description', ''),
                        solution=item.get('solution', ''),
                        severity=self._map_severity(item.get('severity', 'info')),
                        url=item.get('url', ''),
                        host=item.get('host', ''),
                        port=item.get('port', ''),
                        additional_metadata={
                            'nikto_id': item.get('vuln_id', ''),
                        }
                    )
                    parse_result.vulnerabilities.append(vuln)
                    
        except Exception as e:
            parse_result.errors.append(f"Nikto HTML parse error: {str(e)}")
        
        return parse_result

    def save_to_database(self, parsed_data: ParseResult, scan_id: str) -> bool:
        try:
            from tools.models import NiktoResultDb
            
            for vuln in parsed_data.vulnerabilities:
                NiktoResultDb.objects.create(
                    scan_id=vuln.scan_id or scan_id,
                    vuln_id=vuln.vuln_id,
                    name=vuln.title,
                    severity=vuln.severity.value if hasattr(vuln.severity, 'value') else vuln.severity,
                    description=vuln.description,
                    solution=vuln.solution,
                    url=vuln.url,
                    host=vuln.host,
                    port=vuln.port,
                    scanner="Nikto",
                    dup_hash=vuln.dup_hash,
                    date_time=vuln.date_time,
                )
            return True
        except Exception as e:
            logger.error(f"Nikto database save error: {str(e)}")
            return False

    def _map_severity(self, severity: str) -> SeverityLevel:
        mapping = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO,
            'informational': SeverityLevel.INFO,
        }
        return mapping.get(severity.lower(), SeverityLevel.INFO)


class NmapXMLParserAdapter(ResultParserBase):
    """Parser adapter for Nmap XML output"""

    def __init__(self):
        super().__init__(scan_type="network")
        self.supported_formats = [ParseFormat.XML]

    def can_parse(self, file_data: BinaryIO, file_format: str) -> bool:
        if file_format.lower() != 'xml':
            return False
        
        try:
            file_data.seek(0)
            content = file_data.read(1024).decode('utf-8', errors='ignore')
            file_data.seek(0)
            return 'nmaprun' in content.lower()
        except Exception:
            return False

    def parse(self, file_data: BinaryIO) -> ParseResult:
        parse_result = ParseResult()
        
        try:
            from scanners.scanner_parser.network_scanner import nmap_parser
            from django.http import HttpRequest
            
            file_data.seek(0)
            content = file_data.read().decode('utf-8', errors='ignore')
            file_data.seek(0)
            
            request = HttpRequest()
            request.META = {}
            request.user = None
            
            file_obj = io.StringIO(content)
            parsed = nmap_parser.xml_parser(
                file_obj, 
                project_id=None, scan_id=None, username=None
            )
            
            if parsed:
                for item in parsed:
                    vuln = VulnerabilityResult(
                        scan_type=ScanType.NETWORK,
                        scanner_name="Nmap",
                        title=item.get('name', ''),
                        description=item.get('description', ''),
                        solution=item.get('solution', ''),
                        severity=self._map_severity(item.get('severity', 'info')),
                        host=item.get('host', ''),
                        port=item.get('port', ''),
                        additional_metadata={
                            'nmap_id': item.get('vuln_id', ''),
                            'protocol': item.get('protocol', ''),
                            'service': item.get('service', ''),
                        }
                    )
                    parse_result.vulnerabilities.append(vuln)
                    
        except Exception as e:
            parse_result.errors.append(f"Nmap XML parse error: {str(e)}")
        
        return parse_result

    def save_to_database(self, parsed_data: ParseResult, scan_id: str) -> bool:
        try:
            from tools.models import NmapResultDb
            
            for vuln in parsed_data.vulnerabilities:
                NmapResultDb.objects.create(
                    scan_id=vuln.scan_id or scan_id,
                    vuln_id=vuln.vuln_id,
                    name=vuln.title,
                    severity=vuln.severity.value if hasattr(vuln.severity, 'value') else vuln.severity,
                    description=vuln.description,
                    solution=vuln.solution,
                    host=vuln.host,
                    port=vuln.port,
                    scanner="Nmap",
                    dup_hash=vuln.dup_hash,
                    date_time=vuln.date_time,
                    additional_metadata=vuln.additional_metadata,
                )
            return True
        except Exception as e:
            logger.error(f"Nmap database save error: {str(e)}")
            return False

    def _map_severity(self, severity: str) -> SeverityLevel:
        mapping = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO,
            'informational': SeverityLevel.INFO,
        }
        return mapping.get(severity.lower(), SeverityLevel.INFO)


class OpenVASXMLParserAdapter(ResultParserBase):
    """Parser adapter for OpenVAS XML output"""

    def __init__(self):
        super().__init__(scan_type="network")
        self.supported_formats = [ParseFormat.XML]

    def can_parse(self, file_data: BinaryIO, file_format: str) -> bool:
        if file_format.lower() != 'xml':
            return False
        
        try:
            file_data.seek(0)
            content = file_data.read(1024).decode('utf-8', errors='ignore')
            file_data.seek(0)
            return 'report' in content.lower() and 'openvas' in content.lower()
        except Exception:
            return False

    def parse(self, file_data: BinaryIO) -> ParseResult:
        parse_result = ParseResult()
        
        try:
            from scanners.scanner_parser.network_scanner import OpenVas_Parser
            from django.http import HttpRequest
            
            file_data.seek(0)
            content = file_data.read().decode('utf-8', errors='ignore')
            file_data.seek(0)
            
            request = HttpRequest()
            request.META = {}
            request.user = None
            
            file_obj = io.StringIO(content)
            parsed = OpenVas_Parser.xml_parser(
                file_obj, 
                project_id=None, scan_id=None, username=None
            )
            
            if parsed:
                for item in parsed:
                    vuln = VulnerabilityResult(
                        scan_type=ScanType.NETWORK,
                        scanner_name="OpenVAS",
                        title=item.get('name', ''),
                        description=item.get('description', ''),
                        solution=item.get('solution', ''),
                        severity=self._map_severity(item.get('severity', 'info')),
                        host=item.get('host', ''),
                        port=item.get('port', ''),
                        additional_metadata={
                            'openvas_id': item.get('vuln_id', ''),
                            'cve': item.get('cve', ''),
                            'cvss': item.get('cvss', ''),
                        }
                    )
                    parse_result.vulnerabilities.append(vuln)
                    
        except Exception as e:
            parse_result.errors.append(f"OpenVAS XML parse error: {str(e)}")
        
        return parse_result

    def save_to_database(self, parsed_data: ParseResult, scan_id: str) -> bool:
        try:
            from networkscanners.models import NetworkScanResultsDb
            
            for vuln in parsed_data.vulnerabilities:
                NetworkScanResultsDb.objects.create(
                    scan_id=vuln.scan_id or scan_id,
                    vuln_id=vuln.vuln_id,
                    name=vuln.title,
                    severity=vuln.severity.value if hasattr(vuln.severity, 'value') else vuln.severity,
                    description=vuln.description,
                    solution=vuln.solution,
                    host=vuln.host,
                    port=vuln.port,
                    scanner="OpenVAS",
                    dup_hash=vuln.dup_hash,
                    date_time=vuln.date_time,
                    additional_metadata=vuln.additional_metadata,
                )
            return True
        except Exception as e:
            logger.error(f"OpenVAS database save error: {str(e)}")
            return False

    def _map_severity(self, severity: str) -> SeverityLevel:
        mapping = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO,
            'informational': SeverityLevel.INFO,
        }
        return mapping.get(severity.lower(), SeverityLevel.INFO)