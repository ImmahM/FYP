/**
 * Legacy API Compatibility Layer
 * Provides drop-in replacements for legacy API calls using unified endpoints
 * 
 * Usage in templates:
 *   <script src="{% static 'archerysecurity/js/legacy-api-compat.js' %}"></script>
 *   <script>
 *       const api = new LegacyScannerAPI();
 *       // Old: $.getJSON('{% url "webscanners:scan_summaries" %}', { ids: ids.join(',') })
 *       // New: api.webScans.summaries(ids)
 *   </script>
 */

class LegacyScannerAPI {
    constructor() {
        this.client = new UnifiedScannerAPI();
        // Object-literal methods below lose their `this` (=> plugin object, not the
        // instance), so `this.client` would be undefined. Rebind every method to the
        // instance so `api.webScans.delete(...)` etc. resolve `this.client`.
        const groups = [
            'webScans', 'zapScanner', 'networkScans',
            'staticScans', 'cloudScans', 'complianceScans',
            'tools', 'cookies', 'excludedUrls', 'import', 'stats', 'search',
        ];
        for (const group of groups) {
            const obj = this[group];
            if (obj && typeof obj === 'object') {
                for (const key of Object.keys(obj)) {
                    if (typeof obj[key] === 'function') {
                        obj[key] = obj[key].bind(this);
                    }
                }
            }
        }
    }

    // ===== WEB SCANNER COMPATIBILITY =====
    webScans = {
        // GET /webscanners/scan_summaries/?ids=scan_id1,scan_id2
        async summaries(ids) {
            const scanIds = Array.isArray(ids) ? ids : ids.split(',').map(s => s.trim()).filter(Boolean);
            if (scanIds.length === 0) return {};
            return this.client.request('scans/summaries/', {
                method: 'POST',
                body: { scan_ids: scanIds },
            });
        },

        // GET /webscanners/recent_scans/?since=timestamp
        async recent(since) {
            return this.client.listWebScans({ since });
        },

        // GET /webscanners/scan_delete/ (POST with scan_ids)
        async delete(scanIds) {
            const ids = Array.isArray(scanIds) ? scanIds : [scanIds];
            return this.client.request('scans/delete/', {
                method: 'POST',
                body: { scan_ids: ids },
            });
        },

        // GET /webscanners/vuln_delete/ (POST with vuln_ids)
        async vulnDelete(vulnIds) {
            const ids = Array.isArray(vulnIds) ? vulnIds : [vulnIds];
            return this.client.request('scans/vulns/delete/', {
                method: 'POST',
                body: { vuln_ids: ids },
            });
        },

        // POST /webscanners/vuln_mark/ (POST with vuln_id, status)
        async vulnMark(vulnId, status, options = {}) {
            return this.client.request('scans/vulns/mark/', {
                method: 'POST',
                body: { vuln_id: vulnId, status, ...options },
            });
        },

        // GET /webscanners/scan_summaries/ for single scan
        async summary(scanId) {
            return this.summaries([scanId]);
        },

        // GET /webscanners/zap_scan_log/?scan_id=xxx
        async zapLog(scanId) {
            return this.client.request(`scans/${scanId}/log/?type=zap`);
        },

        // Schedule operations
        async schedule(data) {
            return this.client.request('scans/schedule/', {
                method: 'POST',
                body: data,
            });
        },

        async scheduleDelete(scheduleIds) {
            const ids = Array.isArray(scheduleIds) ? scheduleIds : [scheduleIds];
            return this.client.request('scans/schedule/delete/', {
                method: 'POST',
                body: { schedule_ids: ids },
            });
        },
    };

    // ===== ZAP SCANNER COMPATIBILITY =====
    zapScanner = {
        // POST /zapscanner/launch/ (launch ZAP scan)
        async launch(data) {
            return this.client.launchScan({
                ...data,
                scanner_name: 'zap',
                scan_type: 'web',
            });
        },
    };

    // ===== NETWORK SCANNER COMPATIBILITY =====
    networkScans = {
        // GET /networkscanners/scan_summaries/?ids=scan_id1,scan_id2
        async summaries(ids) {
            const scanIds = Array.isArray(ids) ? ids : ids.split(',').map(s => s.trim()).filter(Boolean);
            if (scanIds.length === 0) return {};
            return this.client.request('scans/summaries/', {
                method: 'POST',
                body: { scan_ids: scanIds },
            });
        },

        // GET /networkscanners/recent_scans/?since=timestamp
        async recent(since) {
            return this.client.listNetworkScans({ since });
        },

        // GET /networkscanners/scan_delete/ (POST with scan_ids)
        async delete(scanIds) {
            const ids = Array.isArray(scanIds) ? scanIds : [scanIds];
            return this.client.request('scans/delete/', {
                method: 'POST',
                body: { scan_ids: ids },
            });
        },

        // GET /networkscanners/vuln_delete/ (POST with vuln_ids)
        async vulnDelete(vulnIds) {
            const ids = Array.isArray(vulnIds) ? vulnIds : [vulnIds];
            return this.client.request('scans/vulns/delete/', {
                method: 'POST',
                body: { vuln_ids: ids },
            });
        },

        // POST /networkscanners/vuln_mark/ (POST with vuln_id, status, options)
        async vulnMark(vulnId, status, options = {}) {
            return this.client.request('scans/vulns/mark/', {
                method: 'POST',
                body: { vuln_id: vulnId, status, ...options },
            });
        },

        // POST /networkscanners/launch_scan/
        async launch(data) {
            return this.client.launchScan({
                ...data,
                scan_type: 'network',
            });
        },

        // POST /networkscanners/nmap_launch/
        async nmapLaunch(data) {
            return this.client.launchScan({
                ...data,
                scanner_name: 'nmap',
                scan_type: 'network',
            });
        },

        // POST /networkscanners/openvas_launch/
        async openvasLaunch(data) {
            return this.client.launchScan({
                ...data,
                scanner_name: 'openvas',
                scan_type: 'network',
            });
        },

        // POST /networkscanners/rescan/
        async rescan(scanId) {
            return this.client.request(`scans/${scanId}/rescan/`, {
                method: 'POST',
            });
        },

        // POST /networkscanners/stop/
        async stop(scanId) {
            return this.client.request(`scans/${scanId}/stop/`, {
                method: 'POST',
            });
        },

        // GET /networkscanners/nmap_log/?scan_id=xxx
        async nmapLog(scanId) {
            return this.client.request(`scans/${scanId}/log/?type=nmap`);
        },

        // GET /networkscanners/openvas_log/?scan_id=xxx
        async openvasLog(scanId) {
            return this.client.request(`scans/${scanId}/log/?type=openvas`);
        },

        // GET /networkscanners/scan_row/?scan_id=xxx
        async row(scanId) {
            return this.client.getScan(scanId);
        },

        // Schedule operations
        async schedule(data) {
            return this.client.request('scans/schedule/', {
                method: 'POST',
                body: data,
            });
        },

        async scheduleDelete(scheduleIds) {
            const ids = Array.isArray(scheduleIds) ? scheduleIds : [scheduleIds];
            return this.client.request('scans/schedule/delete/', {
                method: 'POST',
                body: { schedule_ids: ids },
            });
        },
    };

    // ===== STATIC SCANNER COMPATIBILITY =====
    staticScans = {
        async list(params = {}) {
            return this.client.listStaticScans(params);
        },
        async details(scanId) {
            return this.client.getScan(scanId);
        },
        async vulns(scanId, params = {}) {
            return this.client.getScanResults(scanId, params);
        },
    };

    // ===== CLOUD SCANNER COMPATIBILITY =====
    cloudScans = {
        async list(params = {}) {
            return this.client.listCloudScans(params);
        },
        async details(scanId) {
            return this.client.getScan(scanId);
        },
        async vulns(scanId, params = {}) {
            return this.client.getScanResults(scanId, params);
        },
    };

    // ===== COMPLIANCE SCANNER COMPATIBILITY =====
    complianceScans = {
        async list(params = {}) {
            return this.client.listComplianceScans(params);
        },
        async details(scanId) {
            return this.client.getScan(scanId);
        },
        async vulns(scanId, params = {}) {
            return this.client.getScanResults(scanId, params);
        },
    };

    // ===== TOOLS (NIKTO, NMAP, SSLSCAN) =====
    tools = {
        // Nikto
        async niktoLaunch(data) {
            return this.client.launchScan({
                ...data,
                scanner_name: 'nikto',
                scan_type: 'web',
            });
        },
        async niktoLog(scanId) {
            return this.client.request(`scans/${scanId}/log/?type=nikto`);
        },

        // Nmap
        async nmapLaunch(data) {
            return this.client.launchScan({
                ...data,
                scanner_name: 'nmap',
                scan_type: 'network',
            });
        },
        async nmapLog(scanId) {
            return this.client.request(`scans/${scanId}/log/?type=nmap`);
        },

        // SSLScan
        async sslscanLaunch(data) {
            return this.client.launchScan({
                ...data,
                scanner_name: 'sslscan',
                scan_type: 'network',
            });
        },
    };

    // ===== COOKIE MANAGEMENT =====
    cookies = {
        async list(params = {}) {
            return this.client.request('web/cookies/', {
                method: 'GET',
                body: params,
            });
        },
        async add(data) {
            return this.client.request('web/cookies/', {
                method: 'POST',
                body: data,
            });
        },
        async delete(ids) {
            const idArray = Array.isArray(ids) ? ids : [ids];
            return this.client.request('web/cookies/delete/', {
                method: 'POST',
                body: { ids: idArray },
            });
        },
    };

    // ===== EXCLUDED URLs =====
    excludedUrls = {
        async list(params = {}) {
            return this.client.request('web/excluded-urls/', {
                method: 'GET',
                body: params,
            });
        },
        async add(data) {
            return this.client.request('web/excluded-urls/', {
                method: 'POST',
                body: data,
            });
        },
        async delete(ids) {
            const idArray = Array.isArray(ids) ? ids : [ids];
            return this.client.request('web/excluded-urls/delete/', {
                method: 'POST',
                body: { ids: idArray },
            });
        },
    };

    // ===== SCAN IMPORT =====
    import = {
        async upload(formData) {
            return this.client.importResults(formData);
        },
    };

    // ===== STATISTICS =====
    stats = {
        async get() {
            return this.client.getStatistics();
        },
    };

    // ===== SEARCH =====
    search = {
        async vulns(params = {}) {
            return this.client.searchVulnerabilities(params);
        },
    };
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LegacyScannerAPI;
} else {
    window.LegacyScannerAPI = LegacyScannerAPI;
}