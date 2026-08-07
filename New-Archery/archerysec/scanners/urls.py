from django.urls import path
from scanners.views import (
    UnifiedScanListView,
    UnifiedScanDetailView,
    UnifiedScanResultsView,
    UnifiedScanLaunchView,
    UnifiedScanResultImportView,
    UnifiedScanDeleteView,
    ScannerListView,
    ScanStatisticsView,
    VulnerabilitySearchView,
)

urlpatterns = [
    # Scan management
    path('scans/', UnifiedScanListView.as_view(), name='unified-scan-list'),
    path('scans/<uuid:scan_id>/', UnifiedScanDetailView.as_view(), name='unified-scan-detail'),
    path('scans/<uuid:scan_id>/results/', UnifiedScanResultsView.as_view(), name='unified-scan-results'),
    path('scans/launch/', UnifiedScanLaunchView.as_view(), name='unified-scan-launch'),
    path('scans/import/', UnifiedScanResultImportView.as_view(), name='unified-scan-import'),
    path('scans/delete/', UnifiedScanDeleteView.as_view(), name='unified-scan-delete'),
    
    # Scanner registry
    path('scanners/', ScannerListView.as_view(), name='scanner-list'),
    
    # Statistics and search
    path('statistics/', ScanStatisticsView.as_view(), name='scan-statistics'),
    path('vulnerabilities/search/', VulnerabilitySearchView.as_view(), name='vulnerability-search'),
]