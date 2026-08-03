import logging

logger = logging.getLogger(__name__)

SEVERITY_TO_CVSS = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 2.0,
    "informational": 0.0,
    "info": 0.0,
}

CVSS_SEVERITY_THRESHOLDS = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
]


def cvss_score_to_severity(score):
    if score is None:
        return "Informational"
    for threshold, severity in CVSS_SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return "Informational"


def severity_to_cvss_score(severity):
    normalized = (severity or "").strip().lower()
    return SEVERITY_TO_CVSS.get(normalized, 0.0)


def parse_cvss_vector(vector):
    if not vector or not vector.strip():
        return None
    try:
        from cvss import CVSS2, CVSS3, CVSS4
        for cls in (CVSS3, CVSS2, CVSS4):
            try:
                parsed = cls(vector.strip())
                base_score = parsed.scores()[0]
                return {
                    "score": round(base_score, 1),
                    "severity": cvss_score_to_severity(base_score),
                    "vector": vector.strip(),
                    "version": getattr(parsed, "version", "unknown"),
                }
            except Exception:
                continue
    except ImportError:
        logger.debug("cvss library not available, falling back to derived values")
    except Exception as exc:
        logger.debug("Failed to parse CVSS vector '%s': %s", vector, exc)
    return None


class CvssCalculator:
    def compute(self, severity=None, cvss_vector=None, cvss_score=None):
        result = {
            "score": None,
            "severity": None,
            "vector": None,
            "source": None,
        }

        if cvss_vector:
            parsed = parse_cvss_vector(cvss_vector)
            if parsed:
                result["score"] = parsed["score"]
                result["severity"] = parsed["severity"]
                result["vector"] = parsed["vector"]
                result["source"] = "vector"
                return result

        if cvss_score is not None:
            try:
                score = float(cvss_score)
                result["score"] = round(score, 1)
                result["severity"] = cvss_score_to_severity(score)
                result["source"] = "score"
                return result
            except (TypeError, ValueError):
                pass

        if severity:
            derived = severity_to_cvss_score(severity)
            result["score"] = derived
            result["severity"] = cvss_score_to_severity(derived) if derived > 0 else "Informational"
            result["source"] = "severity_derived"
            return result

        return result
