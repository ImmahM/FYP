/**
 * Unified Scanner API Client
 * Modern replacement for legacy API calls
 * Uses the new /scanners/ endpoints
 */
class UnifiedScannerAPI {
    constructor(baseUrl = '') {
        this.baseUrl = baseUrl || '/scanners/';
        this.csrfToken = this.getCookie('csrftoken');
    }

    getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    async request(endpoint, options = {}) {
        const url = this.baseUrl + endpoint;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': this.csrfToken,
            },
            credentials: 'same-origin',
        };

        const mergedOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers,
            },
        };

        if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
            mergedOptions.body = JSON.stringify(options.body);
        }

        const response = await fetch(url, mergedOptions);
        
        if (!response.ok) {
            const error = await response.json().catch(() => ({ error: 'Request failed' }));
            throw new Error(error.error || `HTTP ${response.status}`);
        }

        return response.json();
    }

    // ===== SCAN MANAGEMENT =====
    
    async listScans(params = {}) {
        const queryString = new URLSearchParams(params).toString();
        return this.request(`scans/?${queryString}`);
    }

    async getScan(scanId) {
        return this.request(`scans/${scanId}/`);
    }

    async getScanResults(scanId, params = {}) {
        const queryString = new URLSearchParams(params).toString();
        return this.request(`scans/${scanId}/results/?${queryString}`);
    }

    async launchScan(data) {
        return this.request('scans/launch/', {
            method: 'POST',
            body: data,
        });
    }

    async importResults(formData) {
        return this.request('scans/import/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': this.csrfToken,
            },
            body: formData,
        });
    }

    // ===== STATISTICS & SEARCH =====
    
    async getStatistics() {
        return this.request('statistics/');
    }

    async searchVulnerabilities(params = {}) {
        const queryString = new URLSearchParams(params).toString();
        return this.request(`vulnerabilities/search/?${queryString}`);
    }

    // ===== SCANNER REGISTRY =====
    
    async getScanners() {
        return this.request('scanners/');
    }

    // ===== VULNERABILITY MANAGEMENT =====
    
    /**
     * Mark vulnerability as false positive, closed, open, etc.
     * @param {string} vulnId - Vulnerability ID
     * @param {string} status - New status: 'open', 'closed', 'false_positive', 'risk_accepted', 'in_progress'
     * @param {Object} options - Additional options: { false_positive: 'Yes'|'No', note: '...' }
     */
    async markVulnerability(vulnId, status, options = {}) {
        return this.request('scans/vulns/mark/', {
            method: 'POST',
            body: {
                vuln_id: vulnId,
                status,
                ...options,
            },
        });
    }

    /**
     * Delete one or more vulnerabilities
     * @param {string|string[]} vulnIds - Single ID or array of vulnerability IDs
     */
    async deleteVulnerabilities(vulnIds) {
        const ids = Array.isArray(vulnIds) ? vulnIds : [vulnIds];
        return this.request('scans/vulns/delete/', {
            method: 'POST',
            body: { vuln_ids: ids },
        });
    }

    // ===== SCAN SCHEDULING =====
    
    /**
     * Create or update a scheduled scan
     * @param {Object} data - Schedule configuration
     */
    async scheduleScan(data) {
        return this.request('scans/schedule/', {
            method: 'POST',
            body: data,
        });
    }

    /**
     * Delete scheduled scans
     * @param {string|string[]} scheduleIds - Single ID or array of schedule IDs
     */
    async deleteSchedules(scheduleIds) {
        const ids = Array.isArray(scheduleIds) ? scheduleIds : [scheduleIds];
        return this.request('scans/schedule/delete/', {
            method: 'POST',
            body: { schedule_ids: ids },
        });
    }

    /**
     * Get scan summaries for multiple scans
     * @param {string|string[]} scanIds - Comma-separated string or array of scan IDs
     */
    async getScanSummaries(scanIds) {
        const ids = Array.isArray(scanIds) ? scanIds : scanIds.split(',').map(s => s.trim()).filter(Boolean);
        if (ids.length === 0) return {};
        return this.request('scans/summaries/', {
            method: 'POST',
            body: { scan_ids: ids },
        });
    }

    /**
     * Delete one or more scans
     * @param {string|string[]} scanIds - Single ID or array of scan IDs
     */
    async deleteScans(scanIds) {
        const ids = Array.isArray(scanIds) ? scanIds : [scanIds];
        return this.request('scans/delete/', {
            method: 'POST',
            body: { scan_ids: ids },
        });
    }

    // ===== NETWORK SCAN OPERATIONS =====
    
    /**
     * Stop a running network scan
     * @param {string} scanId - Scan ID to stop
     */
    async stopNetworkScan(scanId) {
        return this.request(`scans/${scanId}/stop/`, {
            method: 'POST',
        });
    }

    /**
     * Rescan (re-run) a network scan
     * @param {string} scanId - Scan ID to rescan
     */
    async rescanNetworkScan(scanId) {
        return this.request(`scans/${scanId}/rescan/`, {
            method: 'POST',
        });
    }

    /**
     * Get scan logs
     * @param {string scanId - Scan ID
     * @type - Log type: 'zap', 'nmap', 'openvas', 'nikto'
     */
    async getScanLog(scanId, type = 'auto') {
        return this.request(`scans/${scanId}/log/?type=${type}`);
    }

    // ===== SCANNER OPERATIONS =====
    
    /**
     * Get scanner status/health
     * @param {string} scannerName - Scanner name: 'zap', 'nikto', 'nmap', 'openvas'
     */
    async getScannerStatus(scannerName) {
        return this.request(`scanners/${scannerName}/status/`);
    }

    /**
     * Launch scanner directly
     * @param {string} scannerName - Scanner name
     * @param {Object} data - Launch configuration
     */
    async launchScanner(scannerName, data) {
        return this.request(`scanners/${scannerName}/launch/`, {
            method: 'POST',
            body: data,
        });
    }

    // ===== LEGACY COMPATIBILITY METHODS =====
    
    // Web scanner compatibility
    async listWebScans(params = {}) {
        return this.listScans({ ...params, scan_type: 'web' });
    }

    async getWebScanResults(scanId, params = {}) {
        return this.getScanResults(scanId, params);
    }

    async launchWebScan(target, scanner = 'zap', options = {}) {
        return this.launchScan({
            scanner_name: scanner,
            scan_type: 'web',
            target,
            options,
        });
    }

    // Network scanner compatibility
    async listNetworkScans(params = {}) {
        return this.listScans({ ...params, scan_type: 'network' });
    }

    async getNetworkScanResults(scanId, params = {}) {
        return this.getScanResults(scanId, params);
    }

    async launchNetworkScan(target, scanner = 'nmap', options = {}) {
        return this.launchScan({
            scanner_name: scanner,
            scan_type: 'network',
            target,
            options,
        });
    }

    // Static/SAST scanner compatibility
    async listStaticScans(params = {}) {
        return this.listScans({ ...params, scan_type: 'static' });
    }

    async getStaticScanResults(scanId, params = {}) {
        return this.getScanResults(scanId, params);
    }

    // Cloud scanner compatibility
    async listCloudScans(params = {}) {
        return this.listScans({ ...params, scan_type: 'cloud' });
    }

    async getCloudScanResults(scanId, params = {}) {
        return this.getScanResults(scanId, params);
    }

    // Compliance scanner compatibility
    async listComplianceScans(params = {}) {
        return this.listScans({ ...params, scan_type: 'compliance' });
    }

    async getComplianceScanResults(scanId, params = {}) {
        return this.getScanResults(scanId, params);
    }

    // ===== LEGACY COMPATIBILITY - NEW OPERATIONS =====
    
    // Web scanner - vulnerability management
    async webScanMarkVuln(vulnId, status, options = {}) {
        return this.markVulnerability(vulnId, status, options);
    }

    async webScanDeleteVulns(vulnIds) {
        return this.deleteVulnerabilities(vulnIds);
    }

    async webScanSchedule(data) {
        return this.scheduleScan(data);
    }

    async webScanScheduleDelete(scheduleIds) {
        return this.deleteSchedules(scheduleIds);
    }

    async webScanSummaries(scanIds) {
        return this.getScanSummaries(scanIds);
    }

    // Network scanner - vulnerability management
    async networkScanMarkVuln(vulnId, status, options = {}) {
        return this.markVulnerability(vulnId, status, options);
    }

    async networkScanDeleteVulns(vulnIds) {
        return this.deleteVulnerabilities(vulnIds);
    }

    async networkScanStop(scanId) {
        return this.stopNetworkScan(scanId);
    }

    async networkScanRescan(scanId) {
        return this.rescanNetworkScan(scanId);
    }

    async networkScanLog(scanId, type = 'auto') {
        return this.getScanLog(scanId, type);
    }

    async networkScanSummaries(scanIds) {
        return this.getScanSummaries(scanIds);
    }

    // Static/Cloud/Compliance scanners
    async staticScanSummaries(scanIds) {
        return this.getScanSummaries(scanIds);
    }

    async cloudScanSummaries(scanIds) {
        return this.getScanSummaries(scanIds);
    }

    async complianceScanSummaries(scanIds) {
        return this.getScanSummaries(scanIds);
    }

    // Scanner operations
    async getScannerStatus(scannerName) {
        return this.request(`scanners/${scannerName}/status/`);
    }

    async launchScanner(scannerName, data) {
        return this.request(`scanners/${scannerName}/launch/`, {
            method: 'POST',
            body: data,
        });
    }
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = UnifiedScannerAPI;
} else {
    window.UnifiedScannerAPI = UnifiedScannerAPI;
}

// Create global instance
const unifiedScannerAPI = new UnifiedScannerAPI();