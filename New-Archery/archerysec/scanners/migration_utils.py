"""
Data Migration Utilities
Migrate legacy scanner results to unified models
"""
import uuid
import logging
from typing import List, Dict, Any
from datetime import datetime

from django.db import transaction
from django.db.models import Q

logger = logging.getLogger(__name__)


class ScanResultMigrator:
    """Handle migration of legacy scan data to unified models"""
    
    # Severity mapping from legacy to unified
    SEVERITY_MAP = {
        'Critical': 'critical',
        'High': 'high', 
        'Medium': 'medium',
        'Low': 'low',
        'Info': 'info',
        'Informational': 'info',
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info',
    }
    
    VULN_STATUS_MAP = {
        'Open': 'open',
        'Fixed': 'fixed',
        'False Positive': 'false_positive',
        'Risk Accepted': 'risk_accepted',
        'In Progress': 'in_progress',
        'open': 'open',
        'fixed': 'fixed',
        'false_positive': 'false_positive',
        'risk_accepted': 'risk_accepted',
        'in_progress': 'in_progress',
    }

    @staticmethod
    def map_severity(legacy_severity: str) -> str:
        """Map legacy severity to unified severity"""
        return ScanResultMigrator.SEVERITY_MAP.get(legacy_severity, 'unknown')

    @staticmethod
    def map_vuln_status(legacy_status: str) -> str:
        """Map legacy vulnerability status to unified status"""
        return ScanResultMigrator.VULN_STATUS_MAP.get(legacy_status, 'open')

    @staticmethod
    def map_false_positive(legacy_fp: str) -> bool:
        """Map legacy false positive string to boolean"""
        return legacy_fp in ('Yes', 'True', 'true', '1', 1, True)

    @staticmethod
    def generate_dup_hash(scan_type: str, scanner_name: str, title: str, 
                          host: str, port: str, path: str, param: str, cve_id: str) -> str:
        """Generate consistent deduplication hash"""
        import hashlib
        key_parts = [scan_type, scanner_name, title, host, port, path, param, cve_id]
        key_string = "|".join(str(p) for p in key_parts if p)
        return hashlib.sha256(key_string.encode()).hexdigest()[:64]

    @transaction.atomic
    def migrate_webscans(self, batch_size: int = 1000) -> Dict[str, int]:
        """Migrate WebScanResultsDb to UnifiedScanResult"""
        from webscanners.models import WebScanResultsDb, WebScansDb
        from scanners.models import UnifiedScanResult, UnifiedScanSummary
        from user_management.models import Organization
        
        stats = {'total': 0, 'migrated': 0, 'skipped': 0, 'errors': 0}
        
        # Get all web scan results
        queryset = WebScanResultsDb.objects.select_related('scan_id', 'organization', 'project').all()
        stats['total'] = queryset.count()
        
        logger.info(f"Starting web scan migration: {stats['total']} records")
        
        for legacy in queryset.iterator(chunk_size=batch_size):
            try:
                # Get scan info
                scan = legacy.scan_id
                if not scan:
                    stats['skipped'] += 1
                    continue
                
                # Build unified vulnerability JSON
                vulnerability = {
                    'title': legacy.title or '',
                    'description': legacy.description or '',
                    'solution': legacy.solution or '',
                    'severity': self.map_severity(legacy.severity),
                    'url': legacy.url or '',
                    'host': legacy.host or '',
                    'port': str(legacy.port) if legacy.port else '',
                    'path': legacy.path or '',
                    'parameter': legacy.param or '',
                    'method': legacy.method or '',
                    'cwe_id': legacy.reference or '',
                    'evidence': legacy.instance or '',
                    'false_positive': self.map_false_positive(legacy.false_positive),
                    'vuln_status': self.map_vuln_status(legacy.vuln_status),
                    'references': legacy.reference.split('\n') if legacy.reference else [],
                    'tags': [],
                }
                
                # Create unified result
                dup_hash = self.generate_dup_hash(
                    'web', scan.scanner or 'unknown',
                    legacy.title, legacy.host, 
                    str(legacy.port) if legacy.port else '',
                    legacy.path, legacy.param,
                    legacy.cve_id if hasattr(legacy, 'cve_id') else ''
                )
                
                UnifiedScanResult.objects.create(
                    scan_id=scan.scan_id,
                    result_id=uuid.uuid4(),
                    scan_type='web',
                    scanner_name=scan.scanner or 'unknown',
                    target=scan.url or '',
                    organization=legacy.organization,
                    project=legacy.project,
                    vulnerability=vulnerability,
                    title=legacy.title or '',
                    description=legacy.description or '',
                    solution=legacy.solution or '',
                    severity=self.map_severity(legacy.severity),
                    cvss_score=legacy.cvss_score if hasattr(legacy, 'cvss_score') else None,
                    cwe_id=legacy.reference or '',
                    cve_id=legacy.cve_id if hasattr(legacy, 'cve_id') else '',
                    url=legacy.url or '',
                    host=legacy.host or '',
                    port=str(legacy.port) if legacy.port else '',
                    path=legacy.path or '',
                    parameter=legacy.param or '',
                    method=legacy.method or '',
                    evidence=legacy.instance or '',
                    dup_hash=dup_hash,
                    false_positive=self.map_false_positive(legacy.false_positive),
                    duplicate=legacy.vuln_duplicate == 'Yes' if hasattr(legacy, 'vuln_duplicate') else False,
                    vuln_status=self.map_vuln_status(legacy.vuln_status),
                    scan_status='completed',
                    started_at=legacy.date_time,
                    completed_at=legacy.date_time,
                    created_by=legacy.created_by,
                )
                stats['migrated'] += 1
                
            except Exception as e:
                logger.error(f"Failed to migrate web scan result {legacy.vuln_id}: {e}")
                stats['errors'] += 1
        
        # Update summaries
        self._update_summaries('web')
        
        logger.info(f"Web scan migration complete: {stats}")
        return stats

    @transaction.atomic
    def migrate_networkscans(self, batch_size: int = 1000) -> Dict[str, int]:
        """Migrate NetworkScanResultsDb to UnifiedScanResult"""
        from networkscanners.models import NetworkScanResultsDb, NetworkScanDb
        from scanners.models import UnifiedScanResult, UnifiedScanSummary
        
        stats = {'total': 0, 'migrated': 0, 'skipped': 0, 'errors': 0}
        
        queryset = NetworkScanResultsDb.objects.select_related('scan_id', 'organization').all()
        stats['total'] = queryset.count()
        
        logger.info(f"Starting network scan migration: {stats['total']} records")
        
        for legacy in queryset.iterator(chunk_size=batch_size):
            try:
                scan = legacy.scan_id
                if not scan:
                    stats['skipped'] += 1
                    continue
                
                vulnerability = {
                    'title': legacy.name or '',
                    'description': legacy.description or '',
                    'solution': legacy.solution or '',
                    'severity': self.map_severity(legacy.severity),
                    'host': legacy.host or '',
                    'port': str(legacy.port) if legacy.port else '',
                    'protocol': legacy.protocol or '',
                    'service': legacy.service or '',
                    'false_positive': self.map_false_positive(legacy.false_positive),
                    'vuln_status': self.map_vuln_status(legacy.vuln_status),
                    'references': [],
                    'tags': [],
                }
                
                dup_hash = self.generate_dup_hash(
                    'network', scan.scanner or 'nmap',
                    legacy.name, legacy.host,
                    str(legacy.port) if legacy.port else '',
                    '', '', legacy.cve_id if hasattr(legacy, 'cve_id') else ''
                )
                
                UnifiedScanResult.objects.create(
                    scan_id=scan.scan_id,
                    result_id=uuid.uuid4(),
                    scan_type='network',
                    scanner_name=scan.scanner or 'nmap',
                    target=scan.target or '',
                    organization=legacy.organization,
                    project=None,  # Network scans may not have project
                    vulnerability=vulnerability,
                    title=legacy.name or '',
                    description=legacy.description or '',
                    solution=legacy.solution or '',
                    severity=self.map_severity(legacy.severity),
                    host=legacy.host or '',
                    port=str(legacy.port) if legacy.port else '',
                    evidence='',
                    dup_hash=dup_hash,
                    false_positive=self.map_false_positive(legacy.false_positive),
                    duplicate=legacy.vuln_duplicate == 'Yes' if hasattr(legacy, 'vuln_duplicate') else False,
                    vuln_status=self.map_vuln_status(legacy.vuln_status),
                    scan_status='completed',
                    started_at=legacy.date_time,
                    completed_at=legacy.date_time,
                    created_by=legacy.created_by,
                )
                stats['migrated'] += 1
                
            except Exception as e:
                logger.error(f"Failed to migrate network scan result {legacy.vuln_id}: {e}")
                stats['errors'] += 1
        
        self._update_summaries('network')
        logger.info(f"Network scan migration complete: {stats}")
        return stats

    @transaction.atomic
    def migrate_staticscans(self, batch_size: int = 1000) -> Dict[str, int]:
        """Migrate StaticScanResultsDb to UnifiedScanResult"""
        from staticscanners.models import StaticScanResultsDb, StaticScansDb
        from scanners.models import UnifiedScanResult, UnifiedScanSummary
        
        stats = {'total': 0, 'migrated': 0, 'skipped': 0, 'errors': 0}
        
        queryset = StaticScanResultsDb.objects.select_related('scan_id', 'organization').all()
        stats['total'] = queryset.count()
        
        logger.info(f"Starting static scan migration: {stats['total']} records")
        
        for legacy in queryset.iterator(chunk_size=batch_size):
            try:
                scan = legacy.scan_id
                if not scan:
                    stats['skipped'] += 1
                    continue
                
                vulnerability = {
                    'title': legacy.name or '',
                    'description': legacy.description or '',
                    'solution': legacy.solution or '',
                    'severity': self.map_severity(legacy.severity),
                    'file_path': legacy.file_path or '',
                    'line_number': legacy.line_number if hasattr(legacy, 'line_number') else None,
                    'rule_id': legacy.rule_id if hasattr(legacy, 'rule_id') else '',
                    'tool': legacy.tool if hasattr(legacy, 'tool') else '',
                    'false_positive': self.map_false_positive(legacy.false_positive) if hasattr(legacy, 'false_positive') else False,
                    'vuln_status': self.map_vuln_status(legacy.vuln_status) if hasattr(legacy, 'vuln_status') else 'open',
                    'references': [],
                    'tags': [],
                }
                
                dup_hash = self.generate_dup_hash(
                    'static', scan.scanner or 'unknown',
                    legacy.name, '', '',
                    legacy.file_path or '', '',
                    legacy.cve_id if hasattr(legacy, 'cve_id') else ''
                )
                
                UnifiedScanResult.objects.create(
                    scan_id=scan.scan_id,
                    result_id=uuid.uuid4(),
                    scan_type='static',
                    scanner_name=scan.scanner or 'unknown',
                    target=scan.target or '',
                    organization=legacy.organization,
                    project=None,
                    vulnerability=vulnerability,
                    title=legacy.name or '',
                    description=legacy.description or '',
                    solution=legacy.solution or '',
                    severity=self.map_severity(legacy.severity),
                    path=legacy.file_path or '',
                    dup_hash=dup_hash,
                    false_positive=vulnerability['false_positive'],
                    vuln_status=vulnerability['vuln_status'],
                    scan_status='completed',
                    started_at=legacy.date_time,
                    completed_at=legacy.date_time,
                    created_by=legacy.created_by,
                )
                stats['migrated'] += 1
                
            except Exception as e:
                logger.error(f"Failed to migrate static scan result {legacy.vuln_id}: {e}")
                stats['errors'] += 1
        
        self._update_summaries('static')
        logger.info(f"Static scan migration complete: {stats}")
        return stats

    @transaction.atomic
    def migrate_cloudscans(self, batch_size: int = 1000) -> Dict[str, int]:
        """Migrate CloudScanResultsDb to UnifiedScanResult"""
        from cloudscanners.models import CloudScansResultsDb, CloudScansDb
        from scanners.models import UnifiedScanResult, UnifiedScanSummary
        
        stats = {'total': 0, 'migrated': 0, 'skipped': 0, 'errors': 0}
        
        queryset = CloudScansResultsDb.objects.select_related('scan_id', 'organization').all()
        stats['total'] = queryset.count()
        
        logger.info(f"Starting cloud scan migration: {stats['total']} records")
        
        for legacy in queryset.iterator(chunk_size=batch_size):
            try:
                scan = legacy.scan_id
                if not scan:
                    stats['skipped'] += 1
                    continue
                
                vulnerability = {
                    'title': legacy.name or '',
                    'description': legacy.description or '',
                    'solution': legacy.solution or '',
                    'severity': self.map_severity(legacy.severity),
                    'resource_id': legacy.resource_id if hasattr(legacy, 'resource_id') else '',
                    'resource_type': legacy.resource_type if hasattr(legacy, 'resource_type') else '',
                    'region': legacy.region if hasattr(legacy, 'region') else '',
                    'provider': legacy.provider if hasattr(legacy, 'provider') else '',
                    'false_positive': self.map_false_positive(legacy.false_positive) if hasattr(legacy, 'false_positive') else False,
                    'vuln_status': self.map_vuln_status(legacy.vuln_status) if hasattr(legacy, 'vuln_status') else 'open',
                    'references': [],
                    'tags': [],
                }
                
                dup_hash = self.generate_dup_hash(
                    'cloud', scan.scanner or 'unknown',
                    legacy.name, '', '',
                    '', '', legacy.cve_id if hasattr(legacy, 'cve_id') else ''
                )
                
                UnifiedScanResult.objects.create(
                    scan_id=scan.scan_id,
                    result_id=uuid.uuid4(),
                    scan_type='cloud',
                    scanner_name=scan.scanner or 'unknown',
                    target=scan.target or '',
                    organization=legacy.organization,
                    project=None,
                    vulnerability=vulnerability,
                    title=legacy.name or '',
                    description=legacy.description or '',
                    solution=legacy.solution or '',
                    severity=self.map_severity(legacy.severity),
                    dup_hash=dup_hash,
                    false_positive=vulnerability['false_positive'],
                    vuln_status=vulnerability['vuln_status'],
                    scan_status='completed',
                    started_at=legacy.date_time,
                    completed_at=legacy.date_time,
                    created_by=legacy.created_by,
                )
                stats['migrated'] += 1
                
            except Exception as e:
                logger.error(f"Failed to migrate cloud scan result {legacy.vuln_id}: {e}")
                stats['errors'] += 1
        
        self._update_summaries('cloud')
        logger.info(f"Cloud scan migration complete: {stats}")
        return stats

    @transaction.atomic
    def migrate_compliancescans(self, batch_size: int = 1000) -> Dict[str, int]:
        """Migrate Compliance scan results to UnifiedScanResult"""
        from compliance.models import InspecScanResultsDb, InspecScanDb, DockleScanResultsDb, DockleScanDb
        from scanners.models import UnifiedScanResult, UnifiedScanSummary
        
        stats = {'total': 0, 'migrated': 0, 'skipped': 0, 'errors': 0}
        
        # Migrate Inspec
        for model, scanner_name in [(InspecScanResultsDb, 'inspec'), (DockleScanResultsDb, 'dockle')]:
            queryset = model.objects.select_related('scan_id', 'organization').all()
            stats['total'] += queryset.count()
        
        logger.info(f"Starting compliance scan migration: {stats['total']} records")
        
        for model, scanner_name in [(InspecScanResultsDb, 'inspec'), (DockleScanResultsDb, 'dockle')]:
            for legacy in queryset.iterator(chunk_size=batch_size):
                try:
                    scan = legacy.scan_id
                    if not scan:
                        stats['skipped'] += 1
                        continue
                    
                    vulnerability = {
                        'title': legacy.title if hasattr(legacy, 'title') else legacy.name or '',
                        'description': legacy.description or '',
                        'solution': legacy.solution if hasattr(legacy, 'solution') else '',
                        'severity': self.map_severity(legacy.severity),
                        'rule_id': legacy.rule_id if hasattr(legacy, 'rule_id') else '',
                        'profile': legacy.profile if hasattr(legacy, 'profile') else '',
                        'false_positive': self.map_false_positive(legacy.false_positive) if hasattr(legacy, 'false_positive') else False,
                        'vuln_status': self.map_vuln_status(legacy.vuln_status) if hasattr(legacy, 'vuln_status') else 'open',
                        'references': [],
                        'tags': [],
                    }
                    
                    dup_hash = self.generate_dup_hash(
                        'compliance', scanner_name,
                        vulnerability['title'], '', '',
                        '', '', ''
                    )
                    
                    UnifiedScanResult.objects.create(
                        scan_id=scan.scan_id,
                        result_id=uuid.uuid4(),
                        scan_type='compliance',
                        scanner_name=scanner_name,
                        target=scan.target if hasattr(scan, 'target') else '',
                        organization=legacy.organization,
                        project=None,
                        vulnerability=vulnerability,
                        title=vulnerability['title'],
                        description=vulnerability['description'],
                        solution=vulnerability['solution'],
                        severity=self.map_severity(legacy.severity),
                        dup_hash=dup_hash,
                        false_positive=vulnerability['false_positive'],
                        vuln_status=vulnerability['vuln_status'],
                        scan_status='completed',
                        started_at=legacy.date_time,
                        completed_at=legacy.date_time,
                        created_by=legacy.created_by,
                    )
                    stats['migrated'] += 1
                    
                except Exception as e:
                    logger.error(f"Failed to migrate {scanner_name} scan result {legacy.vuln_id}: {e}")
                    stats['errors'] += 1
        
        self._update_summaries('compliance')
        logger.info(f"Compliance scan migration complete: {stats}")
        return stats

    def _update_summaries(self, scan_type: str):
        """Update UnifiedScanSummary for a scan type"""
        from scanners.models import UnifiedScanResult, UnifiedScanSummary
        from django.db.models import Count
        
        # Get all scans of this type
        scans = UnifiedScanResult.objects.filter(scan_type=scan_type).values('scan_id').distinct()
        
        for scan_entry in scans:
            scan_id = scan_entry['scan_id']
            results = UnifiedScanResult.objects.filter(scan_id=scan_id)
            
            if not results.exists():
                continue
            
            first = results.first()
            
            # Aggregate counts
            total = results.count()
            severity_counts = results.values('severity').annotate(count=Count('severity'))
            
            summary_data = {
                'scan_id': scan_id,
                'scan_type': scan_type,
                'scanner_name': first.scanner_name,
                'target': first.target,
                'organization': first.organization,
                'project': first.project,
                'total_vulns': total,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'info_count': 0,
                'unknown_count': 0,
                'scan_status': 'completed',
                'started_at': first.started_at,
                'completed_at': first.completed_at,
                'created_by': first.created_by,
            }
            
            for item in severity_counts:
                sev = item['severity']
                count = item['count']
                if sev == 'critical':
                    summary_data['critical_count'] = count
                elif sev == 'high':
                    summary_data['high_count'] = count
                elif sev == 'medium':
                    summary_data['medium_count'] = count
                elif sev == 'low':
                    summary_data['low_count'] = count
                elif sev == 'info':
                    summary_data['info_count'] = count
                else:
                    summary_data['unknown_count'] = count
            
            UnifiedScanSummary.objects.update_or_create(
                scan_id=scan_id,
                defaults=summary_data
            )

    def migrate_all(self, batch_size: int = 1000) -> Dict[str, Dict[str, int]]:
        """Run all migrations"""
        results = {}
        
        logger.info("Starting full migration...")
        
        results['web'] = self.migrate_webscans(batch_size)
        results['network'] = self.migrate_networkscans(batch_size)
        results['static'] = self.migrate_staticscans(batch_size)
        results['cloud'] = self.migrate_cloudscans(batch_size)
        results['compliance'] = self.migrate_compliancescans(batch_size)
        
        logger.info("Full migration complete")
        return results