"""
Example usage of the new scanner architecture in views
"""
from typing import Dict, Any
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from scanners.base import (
    ScannerRegistry, ScanConfig, ScanType, SeverityLevel, ResultMerger
)
from scanners.base.result_models import VulnerabilityResult
from scanners.adapters import ZAPScannerAdapter


class ModernScanLaunchView(APIView):
    """Modern scan launch using unified architecture"""
    
    def post(self, request):
        """Launch a scan using the new architecture"""
        try:
            # Extract scan parameters
            scan_id = request.data.get('scan_id') or str(uuid.uuid4())
            target = request.data.get('target', '')
            scanner_name = request.data.get('scanner', 'zap')
            scan_type = request.data.get('scan_type', 'web')
            organization_id = request.data.get('organization_id')
            project_id = request.data.get('project_id')
            created_by_id = request.user.id if request.user.is_authenticated else None
            options = request.data.get('options', {})
            
            # Create scan configuration
            config = ScanConfig(
                scan_id=scan_id,
                scan_type=ScanType(scan_type),
                scanner_name=scanner_name,
                target=target,
                organization_id=organization_id,
                project_id=project_id,
                created_by_id=created_by_id,
                options=options,
            )
            
            # Get scanner from registry
            scanner = ScannerRegistry.get_scanner_instance(scanner_name, config)
            if not scanner:
                return Response(
                    {'error': f'Scanner {scanner_name} not found'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Run scan
            result = scanner.run()
            
            # Return summary
            return Response({
                'scan_id': scan_id,
                'status': result.scan_status.value,
                'summary': scanner.get_scan_summary(),
                'vulnerabilities': [
                    vuln.to_dict() for vuln in result.vulnerabilities
                ] if hasattr(result, 'vulnerabilities') else [],
            })
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScanResultImportView(APIView):
    """Import scan results using registered parsers"""
    
    def post(self, request):
        """Import and parse scan results"""
        try:
            scan_id = request.data.get('scan_id')
            scan_type = request.data.get('scan_type', 'web')
            file_format = request.data.get('format', 'xml')
            file_data = request.FILES.get('file')
            
            if not file_data:
                return Response(
                    {'error': 'No file provided'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get parser for scan type and format
            parser_class = ScannerRegistry.get_parser_for_format(scan_type, file_format)
            if not parser_class:
                return Response(
                    {'error': f'No parser for {scan_type}/{file_format}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Parse file
            parser = parser_class(scan_type)
            parse_result = parser.parse(file_data)
            
            # Save to database
            success = parser.save_to_database(parse_result, scan_id)
            
            # Deduplicate
            merged = ResultMerger.merge_similar_findings(parse_result.vulnerabilities)
            
            return Response({
                'scan_id': scan_id,
                'total_found': len(parse_result.vulnerabilities),
                'after_dedup': len(merged),
                'errors': parse_result.errors,
                'warnings': parse_result.warnings,
            })
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScannerListView(APIView):
    """List all available scanners and parsers"""
    
    def get(self, request):
        return Response({
            'scanners': ScannerRegistry.list_scanners(),
            'parsers': ScannerRegistry.list_parsers(),
        })


# Example: Custom scanner implementation
class ExampleCustomScanner:
    """Example of how to implement a custom scanner"""
    
    # In practice, this would inherit from ScannerBase
    # class MyCustomScanner(ScannerBase):
    #     def initialize(self) -> bool:
    #         # Setup connection, auth, etc.
    #         return True
    #     
    #     def execute_scan(self) -> ScanResult:
    #         # Run scan, parse results into VulnerabilityResult objects
    #         # Convert to ScanResult
    #         pass
    #     
    #     def get_results(self) -> List[Dict[str, Any]]:
    #         # Return raw results
    #         pass
    #     
    #     def cleanup(self) -> bool:
    #         # Close connections, cleanup temp files
    #         return True
    pass