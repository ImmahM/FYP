import logging

from .cvss_calculator import CvssCalculator
from .nvd_client import NvdLookup

logger = logging.getLogger(__name__)

_nvd = None


def _get_nvd():
    global _nvd
    if _nvd is None:
        _nvd = NvdLookup(request_delay=0.6)
    return _nvd


def enrich_scan_result(obj):
    """Enrich a single scan result model instance with CVSS + NVD data.

    Sets extra attributes on the object so templates can use them directly:
        obj.cvss_score, obj.cvss_severity
        obj.nvd_description, obj.nvd_references (populated only if original is empty)
    """
    severity_label = getattr(obj, "severity", None) or ""
    calculator = CvssCalculator()
    cvss = calculator.compute(severity=severity_label)
    obj.cvss_score = cvss["score"]
    obj.cvss_severity = cvss["severity"]

    existing_desc = (getattr(obj, "description", None) or "").strip()
    existing_ref = (getattr(obj, "reference", None) or "").strip()
    existing_solution = (getattr(obj, "solution", None) or "").strip()

    text_to_search = " ".join(filter(None, [
        getattr(obj, "title", None) or "",
        existing_desc,
        existing_ref,
        existing_solution,
    ]))

    nvd = _get_nvd()
    cve_id = nvd.extract_cve_id(text_to_search)

    nvd_desc = None
    nvd_refs = None
    nvd_solution = None

    if cve_id:
        nvd_data = nvd.fetch(cve_id)
        if nvd_data:
            if nvd_data.get("cvss_score") is not None:
                obj.cvss_score = nvd_data["cvss_score"]
                obj.cvss_severity = nvd_data["cvss_severity"]

            nvd_desc = (nvd_data.get("description") or "").strip()
            if not existing_desc and nvd_desc:
                obj.description = nvd_desc
                obj.nvd_filled_description = True

            nvd_refs = nvd_data.get("references") or []
            if nvd_refs:
                new_refs = [r for r in nvd_refs if r.lower() not in existing_ref.lower()]
                if new_refs:
                    combined = existing_ref
                    if combined:
                        combined += "\n"
                    combined += "\n".join(new_refs)
                    obj.reference = combined.strip()
                    obj.nvd_references = new_refs

    obj.nvd_cve_id = cve_id
    obj.nvd_has_data = bool(cve_id and nvd_desc)

    from .mitre_attack import enrich_model_instance as _mitre_enrich
    _mitre_enrich(obj)
