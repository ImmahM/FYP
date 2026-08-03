"""
Example: Modern Scan Launch View using unified scanner architecture
"""
import uuid
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated

from scanners.base import (
    ScannerRegistry, ScanConfig, ScanType, ScanStatus,
    ResultMerger, VulnerabilityResult
)
from scanners.adapters import ZAPScannerAdapter


class ModernScanLaunchView(APIView):
    """Modern scan launch using unified scanner architecture"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Launch a scan using the new architecture"""
        try:
            # Extract scan parameters
            scan_id = request.data.get('scan_id') or str(uuid.uuid4())
            target = request.data.get('target', '')
            scanner_name = request.data.get('scanner', 'zap')
            scan_type = request.data.get('scan_type', 'web')
            organization_id = getattr(request.user, 'organization_id', None) or request.data.get('organization_id')
            project_id = request.data.get('project_id')
            created_by_id = request.user.id if request.user.is_authenticated else None
            options = request.data.get('options', {})
            
            if not target:
                return Response(
                    {'error': 'Target URL is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if not organization_id:
                return Response(
                    {'error': 'Organization ID is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
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
                available = ScannerRegistry.list_scanners()
                return Response(
                    {'error': f'Scanner "{scanner_name}" not found. Available: {available}'},
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
                    vuln.to_dict() for vuln in getattr(result, 'vulnerabilities', [])
                ],
            })
            
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.exception("Scan launch failed")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScanResultImportView(APIView):
    """Import scan results using registered parsers"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Import and parse scan results"""
        try:
            scan_id = request.data.get('scan_id')
            scan_type = request.data.get('scan_type', 'web')
            file_format = request.data.get('format', 'xml')
            file_data = request.FILES.get('file')
            
            if not scan_id:
                return Response(
                    {'error': 'scan_id is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
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
            
            # Deduplicate results
            merged = ResultMerger.merge_similar_findings(parse_result.vulnerabilities)
            
            # Save to database
            success = parser.save_to_database(parse_result, scan_id)
            
            return Response({
                'scan_id': scan_id,
                'total_found': len(parse_result.vulnerabilities),
                'after_dedup': len(merged),
                'saved': success,
                'errors': parse_result.errors,
                'warnings': parse_result.warnings,
            })
            
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.exception("Scan import failed")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScannerListView(APIView):
    """List all available scanners and parsers"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({
            'scanners': ScannerRegistry.list_scanners(),
            'parsers': ScannerRegistry.list_parsers(),
        })


class ScanStatusView(APIView):
    """Get scan status"""
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        # This would query the database for scan status
        return Response({
            'scan_id': scan_id,
            'status': 'completed',
        })