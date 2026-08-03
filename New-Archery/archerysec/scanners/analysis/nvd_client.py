import logging
import re
import time

import requests

from .cvss_calculator import cvss_score_to_severity

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

PREFERRED_CVSS_SOURCES = {"nvd@nist.gov", "security-advisories@github.com"}


class NvdLookup:
    def __init__(self, api_key=None, request_delay=1.0, use_db_cache=True):
        self.api_key = api_key
        self.request_delay = request_delay
        self.use_db_cache = use_db_cache
        self._cache = {}
        self._last_request = 0.0

    def _rate_limit(self):
        elapsed = time.time() - self._last_request
        if elapsed < self.request_delay:
            time.sleep(self.request_delay - elapsed)

    def _headers(self):
        headers = {"User-Agent": "ArcherySec/1.0 (CVSS Enrichment)"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _db_to_dict(self, db_entry):
        return {
            "cvss_vector": db_entry.cvss_vector,
            "cvss_score": db_entry.cvss_score,
            "cvss_severity": db_entry.cvss_severity,
            "source": db_entry.source,
            "description": db_entry.description,
            "references": db_entry.references or [],
        }

    def _db_get(self, cve_id):
        if not self.use_db_cache:
            return None
        try:
            from scanners.models import NvdCache
            entry = NvdCache.objects.filter(cve_id=cve_id).first()
            if entry:
                return self._db_to_dict(entry)
        except Exception as exc:
            logger.debug("DB cache lookup failed for %s: %s", cve_id, exc)
        return None

    def _db_set(self, cve_id, data):
        if not self.use_db_cache or not data:
            return
        try:
            from scanners.models import NvdCache
            NvdCache.objects.update_or_create(
                cve_id=cve_id,
                defaults={
                    "cvss_score": data.get("cvss_score"),
                    "cvss_severity": data.get("cvss_severity"),
                    "cvss_vector": data.get("cvss_vector"),
                    "description": data.get("description"),
                    "references": data.get("references", []),
                    "source": data.get("source", "nvd"),
                },
            )
        except Exception as exc:
            logger.debug("DB cache write failed for %s: %s", cve_id, exc)

    def fetch(self, cve_id):
        cve_id = cve_id.strip().upper()
        if cve_id in self._cache:
            return self._cache[cve_id]

        db_result = self._db_get(cve_id)
        if db_result is not None:
            self._cache[cve_id] = db_result
            return db_result

        self._rate_limit()
        try:
            resp = requests.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                headers=self._headers(),
                timeout=10,
            )
            self._last_request = time.time()
            if resp.status_code == 200:
                result = self._parse_response(resp.json())
                self._cache[cve_id] = result
                self._db_set(cve_id, result)
                return result
            elif resp.status_code == 404:
                self._cache[cve_id] = None
                return None
            elif resp.status_code == 403:
                logger.warning("NVD API rate limited or forbidden (no API key?) for %s", cve_id)
                self._cache[cve_id] = None
                return None
            else:
                logger.debug("NVD API returned %s for %s", resp.status_code, cve_id)
                self._cache[cve_id] = None
                return None
        except requests.RequestException as exc:
            logger.debug("NVD API request failed for %s: %s", cve_id, exc)
            self._cache[cve_id] = None
            return None

    def _parse_response(self, data):
        try:
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            cve_data = vulns[0].get("cve", {})
            metrics = cve_data.get("metrics", {})
            vector = None
            score = None
            severity = None

            cvss_data = self._best_cvss_data(metrics)
            if cvss_data:
                vector = cvss_data.get("vectorString")
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")
                if score is not None:
                    score = round(float(score), 1)
                if severity:
                    severity = severity.capitalize()
                else:
                    severity = cvss_score_to_severity(score)

            if not vector and not score:
                return None

            # Extract English description
            descriptions = cve_data.get("descriptions", [])
            nvd_description = None
            for desc in descriptions:
                if desc.get("lang") == "en":
                    nvd_description = desc.get("value")
                    break

            # Extract references
            refs = cve_data.get("references", [])
            nvd_references = []
            for ref in refs:
                url = ref.get("url")
                if url:
                    nvd_references.append(url)

            return {
                "cvss_vector": vector,
                "cvss_score": score,
                "cvss_severity": severity,
                "source": "nvd",
                "description": nvd_description,
                "references": nvd_references,
            }
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            logger.debug("Failed to parse NVD response: %s", exc)
            return None

    def _best_cvss_data(self, metrics):
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(metric_key, [])
            if not entries:
                continue
            primary = None
            best = None
            for entry in entries:
                src = (entry.get("source") or "").lower()
                typ = (entry.get("type") or "").lower()
                if typ == "primary":
                    primary = entry.get("cvssData")
                    break
                if src in {s.lower() for s in PREFERRED_CVSS_SOURCES}:
                    if best is None:
                        best = entry.get("cvssData")
            if primary:
                return primary
            if best:
                return best
            return entries[0].get("cvssData")

        v2_entries = metrics.get("cvssMetricV2", [])
        if v2_entries:
            cvss_data = v2_entries[0].get("cvssData")
            return cvss_data

        return None

    def extract_cve_id(self, text):
        if not text:
            return None
        match = CVE_RE.search(text)
        return match.group(0).upper() if match else None

    def enrich_finding(self, finding):
        cve_id = self.extract_cve_id(finding.get("title", ""))
        if not cve_id:
            cve_id = self.extract_cve_id(finding.get("description", ""))

        if not cve_id:
            return

        nvd_data = self.fetch(cve_id)
        if not nvd_data:
            return

        if nvd_data.get("cvss_score") is not None:
            finding["cvss_score"] = nvd_data["cvss_score"]
            finding["cvss_severity"] = nvd_data["cvss_severity"]

        # Fill empty description from NVD
        existing_desc = (finding.get("description") or "").strip()
        nvd_desc = (nvd_data.get("description") or "").strip()
        if not existing_desc and nvd_desc:
            finding["description"] = nvd_desc

        # Append NVD references to existing references
        nvd_refs = nvd_data.get("references") or []
        existing_ref = (finding.get("reference") or "").strip()
        if nvd_refs:
            new_refs = [r for r in nvd_refs if r.lower() not in existing_ref.lower()]
            if new_refs:
                combined = existing_ref + "\n" + "\n".join(new_refs) if existing_ref else "\n".join(new_refs)
                finding["reference"] = combined.strip()
