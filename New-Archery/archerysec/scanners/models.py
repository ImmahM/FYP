"""
Unified Scan Models
Replaces WebScanResultsDb, NetworkScanResultsDb, StaticScanResultsDb, CloudScanResultsDb, ComplianceScanResultsDb
"""
from django.db import models
from django.contrib.auth import get_user_model
import uuid

from user_management.models import Organization, UserProfile


class AuditAction(models.TextChoices):
    LOGIN = "login", "Login"
    LOGOUT = "logout", "Logout"
    LOGIN_FAILED = "login_failed", "Login Failed"
    SCAN_START = "scan_start", "Scan Started"
    SCAN_COMPLETE = "scan_complete", "Scan Completed"
    REPORT_DOWNLOAD = "report_download", "Report Downloaded"
    USER_CREATED = "user_created", "User Created"
    USER_UPDATED = "user_updated", "User Updated"
    USER_DELETED = "user_deleted", "User Deleted"
    SETTINGS_CHANGED = "settings_changed", "Settings Changed"
    PASSWORD_CHANGED = "password_changed", "Password Changed"
    API_ACCESS = "api_access", "API Access"
from projects.models import ProjectDb


class ScanType(models.TextChoices):
    WEB = "web", "Web Application"
    NETWORK = "network", "Network"
    STATIC = "static", "Static Code Analysis"
    CLOUD = "cloud", "Cloud Infrastructure"
    COMPLIANCE = "compliance", "Compliance"
    CONTAINER = "container", "Container"
    SAST = "sast", "SAST"
    DAST = "dast", "DAST"


class ScanStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    RUNNING = "running", "Running"
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"
    CANCELLED = "cancelled", "Cancelled"


class SeverityLevel(models.TextChoices):
    CRITICAL = "critical", "Critical"
    HIGH = "high", "High"
    MEDIUM = "medium", "Medium"
    LOW = "low", "Low"
    INFO = "info", "Informational"
    UNKNOWN = "unknown", "Unknown"


class VulnStatus(models.TextChoices):
    OPEN = "open", "Open"
    FIXED = "fixed", "Fixed"
    FALSE_POSITIVE = "false_positive", "False Positive"
    RISK_ACCEPTED = "risk_accepted", "Risk Accepted"
    IN_PROGRESS = "in_progress", "In Progress"


class UnifiedScanConfig(models.Model):
    """Unified scan configuration for all scanner types"""
    
    scan_id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    scan_type = models.CharField(max_length=20, choices=ScanType.choices)
    scanner_name = models.CharField(max_length=50)
    
    # Target and scope
    target = models.TextField()
    targets = models.JSONField(default=list, blank=True)
    
    # Execution parameters
    profile = models.CharField(max_length=50, blank=True, null=True)
    options = models.JSONField(default=dict, blank=True)
    timeout = models.IntegerField(default=3600)
    
    # Scheduling
    schedule_config = models.JSONField(blank=True, null=True)
    schedule_type = models.CharField(max_length=20, blank=True, null=True)
    
    # Organization
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    project = models.ForeignKey(ProjectDb, on_delete=models.SET_NULL, blank=True, null=True)
    created_by = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = "unified_scan_config"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["scan_type", "organization"]),
            models.Index(fields=["scanner_name", "organization"]),
        ]
    
    def __str__(self):
        return f"{self.scan_type} - {self.scanner_name} - {self.target[:50]}"


class UnifiedScanResult(models.Model):
    """Unified vulnerability scan result for ALL scanner types"""
    
    scan_id = models.UUIDField(default=uuid.uuid4)
    result_id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    
    # Scanner identification
    scan_type = models.CharField(max_length=20, choices=ScanType.choices)
    scanner_name = models.CharField(max_length=50)
    
    # Target information
    target = models.TextField()
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    project = models.ForeignKey(ProjectDb, on_delete=models.SET_NULL, blank=True, null=True)
    
    # Vulnerability details (unified structure)
    vulnerability = models.JSONField(default=dict)
    
    # Standardized fields for querying/filtering
    title = models.CharField(max_length=500, blank=True)
    description = models.TextField(blank=True)
    solution = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=SeverityLevel.choices, default=SeverityLevel.INFO)
    cvss_score = models.DecimalField(max_digits=4, decimal_places=1, blank=True, null=True)
    cvss_vector = models.CharField(max_length=100, blank=True)
    cwe_id = models.CharField(max_length=20, blank=True)
    cve_id = models.CharField(max_length=20, blank=True)
    
    # Location context
    url = models.TextField(blank=True)
    host = models.CharField(max_length=255, blank=True)
    port = models.CharField(max_length=10, blank=True)
    path = models.CharField(max_length=500, blank=True)
    parameter = models.CharField(max_length=255, blank=True)
    method = models.CharField(max_length=10, blank=True)
    
    # Evidence
    evidence = models.TextField(blank=True)
    request = models.TextField(blank=True)
    response = models.TextField(blank=True)
    payload = models.TextField(blank=True)
    
    # Tracking
    dup_hash = models.CharField(max_length=64, blank=True, db_index=True)
    false_positive = models.BooleanField(default=False)
    duplicate = models.BooleanField(default=False)
    vuln_status = models.CharField(max_length=20, choices=VulnStatus.choices, default=VulnStatus.OPEN)
    
    # References
    references = models.JSONField(default=list, blank=True)
    tags = models.JSONField(default=list, blank=True)
    
    # Scan metadata
    scan_status = models.CharField(max_length=20, choices=ScanStatus.choices, default=ScanStatus.PENDING)
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    failure_reason = models.TextField(blank=True, null=True)
    
    # Ownership
    created_by = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = "unified_scan_result"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["scan_id", "scan_type"]),
            models.Index(fields=["scan_type", "organization"]),
            models.Index(fields=["scanner_name", "organization"]),
            models.Index(fields=["severity", "organization"]),
            models.Index(fields=["dup_hash", "organization"]),
            models.Index(fields=["vuln_status", "organization"]),
            models.Index(fields=["created_at"]),
        ]
        unique_together = [["scan_id", "result_id"]]
    
    def __str__(self):
        return f"{self.scan_type}/{self.scanner_name} - {self.title[:50]} - {self.severity}"


class UnifiedScanSummary(models.Model):
    """Aggregated scan summary for quick dashboard queries"""
    
    scan_id = models.UUIDField(primary_key=True)
    scan_type = models.CharField(max_length=20, choices=ScanType.choices)
    scanner_name = models.CharField(max_length=50)
    
    target = models.TextField()
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    project = models.ForeignKey(ProjectDb, on_delete=models.SET_NULL, blank=True, null=True)
    
    # Counts by severity
    total_vulns = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)
    unknown_count = models.IntegerField(default=0)
    
    # Status
    scan_status = models.CharField(max_length=20, choices=ScanStatus.choices, default=ScanStatus.PENDING)
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    failure_reason = models.TextField(blank=True, null=True)
    
    # Ownership
    created_by = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = "unified_scan_summary"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["scan_type", "organization"]),
            models.Index(fields=["scan_status", "organization"]),
        ]
    
    def __str__(self):
        return f"{self.scan_id} - {self.scan_type} - {self.total_vulns} vulns"


class NvdCache(models.Model):
    """Persistent cache for NVD API lookups to avoid redundant requests."""
    cve_id = models.CharField(max_length=20, unique=True, primary_key=True)
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_severity = models.CharField(max_length=20, null=True, blank=True)
    cvss_vector = models.TextField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    references = models.JSONField(null=True, blank=True, default=list)
    source = models.CharField(max_length=20, default="nvd")
    fetched_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "nvd_cache"
        verbose_name = "NVD Cache Entry"
        verbose_name_plural = "NVD Cache Entries"

    def __str__(self):
        return f"{self.cve_id} - CVSS {self.cvss_score} / {self.cvss_severity}"


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        UserProfile, on_delete=models.SET_NULL, null=True, blank=True
    )
    action = models.CharField(max_length=30, choices=AuditAction.choices)
    resource_type = models.CharField(max_length=30, blank=True)
    resource_id = models.CharField(max_length=100, blank=True)
    details = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "audit_log"
        verbose_name = "Audit Log Entry"
        verbose_name_plural = "Audit Log Entries"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["action"]),
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["resource_type", "resource_id"]),
        ]

    def __str__(self):
        return f"{self.created_at.isoformat()} - {self.action} - {self.user}"