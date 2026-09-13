"""
Unified Scan API Views
Replaces separate webscanners, networkscanners, staticscanners views with unified endpoints
"""
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q, Count
from django.utils import timezone
import uuid

from scanners.models import UnifiedScanResult, UnifiedScanSummary, UnifiedScanConfig
from scanners.base import ScannerRegistry, ScanConfig, ScanType, ScanStatus
from user_management.models import Organization


class UnifiedScanListView(APIView):
    """Unified scan listing endpoint for all scanner types"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """List scans with filtering"""
        try:
            # Get query parameters
            scan_type = request.GET.get('scan_type')  # web, network, static, cloud, compliance
            scanner_name = request.GET.get('scanner')  # zap, nikto, nmap, openvas
            severity = request.GET.get('severity')  # critical, high, medium, low, info
            vuln_status = request.GET.get('vuln_status')  # open, fixed, false_positive
            project_id = request.GET.get('project_id')
            organization_id = getattr(request.user, 'organization_id', None)
            page = int(request.GET.get('page', 1))
            page_size = int(request.GET.get('page_size', 20))
            
            # Base queryset
            queryset = UnifiedScanSummary.objects.select_related('organization', 'project', 'created_by')
            
            # Filter by organization (multi-tenant)
            if organization_id:
                queryset = queryset.filter(organization_id=organization_id)
            
            # Apply filters
            if scan_type:
                queryset = queryset.filter(scan_type=scan_type)
            
            if scanner_name:
                queryset = queryset.filter(scanner_name=scanner_name)
            
            if project_id:
                queryset = queryset.filter(project_id=project_id)
            
            # Order by most recent
            queryset = queryset.order_by('-created_at')
            
            # Pagination
            total = queryset.count()
            start = (page - 1) * page_size
            end = start + page_size
            scans = queryset[start:end]
            
            # Build response
            results = []
            for scan in scans:
                results.append({
                    'scan_id': str(scan.scan_id),
                    'scan_type': scan.scan_type,
                    'scanner_name': scan.scanner_name,
                    'target': scan.target[:100] if scan.target else '',
                    'organization': scan.organization.name if scan.organization else None,
                    'project': scan.project.name if scan.project else None,
                    'total_vulns': scan.total_vulns,
                    'severity_counts': {
                        'critical': scan.critical_count,
                        'high': scan.high_count,
                        'medium': scan.medium_count,
                        'low': scan.low_count,
                        'info': scan.info_count,
                        'unknown': scan.unknown_count,
                    },
                    'scan_status': scan.scan_status,
                    'started_at': scan.started_at.isoformat() if scan.started_at else None,
                    'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                    'created_at': scan.created_at.isoformat() if scan.created_at else None,
                })
            
            return Response({
                'results': results,
                'pagination': {
                    'page': page,
                    'page_size': page_size,
                    'total': total,
                    'total_pages': (total + page_size - 1) // page_size,
                }
            })
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UnifiedScanDetailView(APIView):
    """Get detailed scan information"""
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        """Get scan summary and details"""
        try:
            organization_id = getattr(request.user, 'organization_id', None)
            
            scan = UnifiedScanSummary.objects.select_related('organization', 'project').get(
                scan_id=scan_id,
                organization_id=organization_id
            )
            
            return Response({
                'scan_id': str(scan.scan_id),
                'scan_type': scan.scan_type,
                'scanner_name': scan.scanner_name,
                'target': scan.target,
                'organization': scan.organization.name if scan.organization else None,
                'project': scan.project.name if scan.project else None,
                'total_vulns': scan.total_vulns,
                'severity_counts': {
                    'critical': scan.critical_count,
                    'high': scan.high_count,
                    'medium': scan.medium_count,
                    'low': scan.low_count,
                    'info': scan.info_count,
                    'unknown': scan.unknown_count,
                },
                'scan_status': scan.scan_status,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'failure_reason': scan.failure_reason,
                'created_at': scan.created_at.isoformat() if scan.created_at else None,
            })
            
        except UnifiedScanSummary.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UnifiedScanResultsView(APIView):
    """Unified scan results/vulnerabilities endpoint"""
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        """Get all vulnerabilities for a scan"""
        try:
            organization_id = getattr(request.user, 'organization_id', None)
            
            # Verify scan exists and user has access
            scan = UnifiedScanSummary.objects.filter(
                scan_id=scan_id,
                organization_id=organization_id
            ).first()
            
            if not scan:
                return Response(
                    {'error': 'Scan not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Get query parameters for filtering results
            severity = request.GET.get('severity')
            vuln_status = request.GET.get('vuln_status')
            false_positive = request.GET.get('false_positive')
            page = int(request.GET.get('page', 1))
            page_size = int(request.GET.get('page_size', 50))
            
            queryset = UnifiedScanResult.objects.filter(scan_id=scan_id)
            
            if severity:
                queryset = queryset.filter(severity=severity)
            
            if vuln_status:
                queryset = queryset.filter(vuln_status=vuln_status)
            
            if false_positive is not None:
                queryset = queryset.filter(false_positive=false_positive.lower() == 'true')
            
            queryset = queryset.order_by('-severity', '-created_at')
            
            total = queryset.count()
            start = (page - 1) * page_size
            end = start + page_size
            results = queryset[start:end]
            
            vulnerabilities = []
            for vuln in results:
                vulnerabilities.append(vuln.vulnerability)
            
            return Response({
                'scan_id': str(scan_id),
                'scan_type': scan.scan_type,
                'scanner_name': scan.scanner_name,
                'total': total,
                'page': page,
                'page_size': page_size,
                'total_pages': (total + page_size - 1) // page_size,
                'vulnerabilities': vulnerabilities,
            })
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UnifiedScanLaunchView(APIView):
    """Launch a new scan using unified architecture"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Launch scan using registered scanner adapters"""
        try:
            organization_id = getattr(request.user, 'organization_id', None)
            if not organization_id:
                return Response(
                    {'error': 'User must belong to an organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Extract parameters
            scanner_name = request.data.get('scanner')  # zap, nikto, nmap, openvas
            scan_type = request.data.get('scan_type', 'web')
            target = request.data.get('target', '')
            project_id = request.data.get('project_id')
            options = request.data.get('options', {})
            schedule_config = request.data.get('schedule_config')
            
            if not scanner_name:
                return Response(
                    {'error': 'Scanner name is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if not target:
                return Response(
                    {'error': 'Target is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get scanner from registry
            scanner_class = ScannerRegistry.get_scanner(scanner_name)
            if not scanner_class:
                available = ScannerRegistry.list_scanners()
                return Response(
                    {'error': f'Scanner "{scanner_name}" not found. Available: {available}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create scan config
            scan_id = str(uuid.uuid4())
            config = ScanConfig(
                scan_id=scan_id,
                scan_type=ScanType(scan_type),
                scanner_name=scanner_name,
                target=target,
                organization_id=organization_id,
                project_id=project_id,
                created_by_id=request.user.id,
                options=options,
            )
            
            # Save scan config
            UnifiedScanConfig.objects.create(
                scan_id=scan_id,
                scan_type=scan_type,
                scanner_name=scanner_name,
                target=target,
                options=options,
                organization_id=organization_id,
                project_id=project_id,
                created_by_id=request.user.id,
                schedule_config=schedule_config,
            )
            
            # Create scan summary entry
            UnifiedScanSummary.objects.create(
                scan_id=scan_id,
                scan_type=scan_type,
                scanner_name=scanner_name,
                target=target,
                organization_id=organization_id,
                project_id=project_id,
                scan_status='pending',
                created_by_id=request.user.id,
            )
            
            # Get scanner instance and run asynchronously
            # In production, this would be a Celery task
            scanner = scanner_class(config)
            
            # Return immediate response with scan_id
            return Response({
                'scan_id': scan_id,
                'status': 'pending',
                'message': 'Scan initiated',
                'scanner': scanner_name,
                'target': target,
            })
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UnifiedScanResultImportView(APIView):
    """Import scan results from external tools"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Import and parse scan results file"""
        try:
            organization_id = getattr(request.user, 'organization_id', None)
            
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
            
            # Save to unified database
            success = parser.save_to_database(parse_result, scan_id)
            
            # Update scan summary
            from scanners.migration_utils import ScanResultMigrator
            migrator = ScanResultMigrator()
            migrator._update_summaries(scan_type)
            
            return Response({
                'scan_id': scan_id,
                'total_found': len(parse_result.vulnerabilities),
                'saved': success,
                'errors': parse_result.errors,
                'warnings': parse_result.warnings,
            })
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UnifiedScanDeleteView(APIView):
    """Delete one or more scans"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Delete scans by scan_ids"""
        try:
            organization_id = getattr(request.user, 'organization_id', None)
            if not organization_id:
                return Response(
                    {'error': 'User must belong to an organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            scan_ids = request.data.get('scan_ids', [])
            if not scan_ids:
                return Response(
                    {'error': 'scan_ids is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Ensure scan_ids is a list
            if not isinstance(scan_ids, list):
                scan_ids = [scan_ids]

            # Non-admins can only delete their own scans
            try:
                is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
            except Exception:
                is_admin = False

            queryset = UnifiedScanSummary.objects.filter(
                scan_id__in=scan_ids,
                organization_id=organization_id
            )
            if not is_admin:
                queryset = queryset.filter(created_by_id=request.user.id)

            deleted_count, _ = queryset.delete()

            return Response({
                'deleted_count': deleted_count,
                'message': f'Successfully deleted {deleted_count} scan(s)'
            })

        except Exception as e:
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
            'scan_types': [choice.value for choice in ScanType],
        })


class ScanStatisticsView(APIView):
    """Get scan statistics for dashboard"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        organization_id = getattr(request.user, 'organization_id', None)
        
        queryset = UnifiedScanSummary.objects.all()
        if organization_id:
            queryset = queryset.filter(organization_id=organization_id)
        
        # Overall stats
        total_scans = queryset.count()
        total_vulns = queryset.aggregate(total=Count('total_vulns'))['total'] or 0
        
        # By scan type
        by_type = queryset.values('scan_type').annotate(
            count=Count('scan_id'),
            vulns=Count('total_vulns')
        ).order_by('-count')
        
        # By scanner
        by_scanner = queryset.values('scanner_name').annotate(
            count=Count('scan_id'),
            vulns=Count('total_vulns')
        ).order_by('-count')
        
        # By status
        by_status = queryset.values('scan_status').annotate(
            count=Count('scan_id')
        ).order_by('-count')
        
        # By severity (from results)
        severity_stats = UnifiedScanResult.objects.filter(
            organization_id=organization_id
        ).values('severity').annotate(
            count=Count('result_id')
        ).order_by('-count')
        
        return Response({
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulns,
            'by_scan_type': list(by_type),
            'by_scanner': list(by_scanner),
            'by_status': list(by_status),
            'by_severity': list(severity_stats),
        })


class VulnerabilitySearchView(APIView):
    """Search vulnerabilities across all scans"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        organization_id = getattr(request.user, 'organization_id', None)
        
        # Search parameters
        query = request.GET.get('q', '')
        scan_type = request.GET.get('scan_type')
        severity = request.GET.get('severity')
        cve_id = request.GET.get('cve_id')
        host = request.GET.get('host')
        project_id = request.GET.get('project_id')
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 20))
        
        queryset = UnifiedScanResult.objects.select_related('organization', 'project')
        
        if organization_id:
            queryset = queryset.filter(organization_id=organization_id)
        
        if scan_type:
            queryset = queryset.filter(scan_type=scan_type)
        
        if severity:
            queryset = queryset.filter(severity=severity)
        
        if cve_id:
            queryset = queryset.filter(cve_id__icontains=cve_id)
        
        if host:
            queryset = queryset.filter(host__icontains=host)
        
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        
        if query:
            queryset = queryset.filter(
                Q(title__icontains=query) |
                Q(description__icontains=query) |
                Q(vulnerability__icontains=query)
            )
        
        queryset = queryset.order_by('-severity', '-created_at')
        
        total = queryset.count()
        start = (page - 1) * page_size
        end = start + page_size
        results = queryset[start:end]
        
        vulnerabilities = []
        for vuln in results:
            vulnerabilities.append({
                'result_id': str(vuln.result_id),
                'scan_id': str(vuln.scan_id),
                'scan_type': vuln.scan_type,
                'scanner_name': vuln.scanner_name,
                'title': vuln.title,
                'severity': vuln.severity,
                'host': vuln.host,
                'port': vuln.port,
                'url': vuln.url,
                'cve_id': vuln.cve_id,
                'cwe_id': vuln.cwe_id,
                'false_positive': vuln.false_positive,
                'vuln_status': vuln.vuln_status,
                'created_at': vuln.created_at.isoformat() if vuln.created_at else None,
            })
        
        return Response({
            'results': vulnerabilities,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total': total,
                'total_pages': (total + page_size - 1) // page_size,
            }
        })