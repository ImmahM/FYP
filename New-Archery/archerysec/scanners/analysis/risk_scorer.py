from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
from scanners.base.result_models import SeverityLevel


class PriorityTier(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PriorityScore:
    score: float = 0.0
    tier: PriorityTier = PriorityTier.INFO
    confidence: str = "low"
    factors: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


SEVERITY_BASE_SCORE = {
    SeverityLevel.CRITICAL: 90,
    SeverityLevel.HIGH: 70,
    SeverityLevel.MEDIUM: 50,
    SeverityLevel.LOW: 25,
    SeverityLevel.INFO: 5,
    SeverityLevel.UNKNOWN: 10,
}

CVSS_SEVERITY_THRESHOLDS = [
    (9.0, SeverityLevel.CRITICAL),
    (7.0, SeverityLevel.HIGH),
    (4.0, SeverityLevel.MEDIUM),
    (0.1, SeverityLevel.LOW),
]


def _cvss_to_tier(cvss: float) -> SeverityLevel:
    for threshold, tier in CVSS_SEVERITY_THRESHOLDS:
        if cvss >= threshold:
            return tier
    return SeverityLevel.INFO


def _cvss_norm(cvss: Optional[float]) -> float:
    if cvss is not None and cvss > 0:
        return min(cvss / 10.0, 1.0)
    return 0.0


def _has_cve(cve_id: str) -> bool:
    return bool(cve_id) and cve_id.startswith("CVE-")


class RiskScorer:
    """Rule-based risk scorer combining severity, CVSS, exploitability, and asset context."""

    def score(
        self,
        severity: SeverityLevel,
        cvss_score: Optional[float] = None,
        cve_id: str = "",
        has_evidence: bool = False,
        asset_priority: int = 0,
    ) -> PriorityScore:
        base = SEVERITY_BASE_SCORE.get(severity, 10)
        cvss_bonus = 0.0
        if cvss_score is not None and cvss_score > 0:
            cvss_bonus = _cvss_norm(cvss_score) * 20
            cvss_tier = _cvss_to_tier(cvss_score)
            sev_tier_weight = SEVERITY_BASE_SCORE.get(severity, 10)
            cvss_tier_weight = SEVERITY_BASE_SCORE.get(cvss_tier, 10)
            if cvss_tier_weight > sev_tier_weight:
                base = max(base, cvss_tier_weight)

        exploit_bonus = 15.0 if _has_cve(cve_id) else 0.0
        evidence_bonus = 5.0 if has_evidence else 0.0
        asset_bonus = min(asset_priority * 2, 10.0)

        raw_score = base + cvss_bonus + exploit_bonus + evidence_bonus + asset_bonus
        score = min(raw_score, 100.0)

        tier = self._determine_tier(score, severity, cvss_score)
        confidence = self._confidence(severity, cvss_score, cve_id)
        recommendation = self._recommendation(tier, severity, cve_id)

        return PriorityScore(
            score=round(score, 1),
            tier=tier,
            confidence=confidence,
            factors={
                "severity": severity.value,
                "cvss_score": cvss_score,
                "has_cve": _has_cve(cve_id),
                "has_evidence": has_evidence,
                "asset_priority": asset_priority,
                "base_score": round(base, 1),
                "cvss_bonus": round(cvss_bonus, 1),
                "exploit_bonus": exploit_bonus,
                "evidence_bonus": evidence_bonus,
                "asset_bonus": asset_bonus,
            },
            recommendation=recommendation,
        )

    def score_finding(self, finding: Dict[str, Any]) -> PriorityScore:
        sev_str = finding.get("severity", "info")
        try:
            severity = SeverityLevel(sev_str.lower())
        except ValueError:
            severity = SeverityLevel.UNKNOWN
        cvss = finding.get("cvss_score")
        if cvss is not None:
            try:
                cvss = float(cvss)
            except (TypeError, ValueError):
                cvss = None
        cve_id = finding.get("cve_id", "")
        has_evidence = bool(finding.get("evidence") or finding.get("instance"))
        asset_priority = int(finding.get("asset_priority", 0))
        return self.score(
            severity=severity,
            cvss_score=cvss,
            cve_id=cve_id,
            has_evidence=has_evidence,
            asset_priority=asset_priority,
        )

    def score_summary(self, counts: Dict[str, int]) -> PriorityScore:
        tier_scores = {
            "critical": 90, "high": 70, "medium": 50, "low": 25, "info": 5
        }
        total_weight = sum(
            counts.get(sev, 0) * weight for sev, weight in tier_scores.items()
        )
        total_count = sum(counts.get(sev, 0) for sev in tier_scores)
        if total_count == 0:
            return PriorityScore(score=0.0, tier=PriorityTier.INFO, confidence="high", factors={"method": "summary_weighted"})
        avg = total_weight / total_count
        raw = min(avg * 1.2, 100.0)
        tier = self._determine_tier(raw, None, None)
        return PriorityScore(
            score=round(raw, 1),
            tier=tier,
            confidence="medium",
            factors={"method": "summary_weighted", "total_count": total_count, "weighted_average": round(avg, 1)},
        )

    def _determine_tier(
        self,
        score: float,
        severity: Optional[SeverityLevel],
        cvss: Optional[float],
    ) -> PriorityTier:
        if score >= 75:
            return PriorityTier.CRITICAL
        if score >= 55:
            return PriorityTier.HIGH
        if score >= 35:
            return PriorityTier.MEDIUM
        if score >= 15:
            return PriorityTier.LOW
        return PriorityTier.INFO

    def _confidence(self, severity: SeverityLevel, cvss: Optional[float], cve_id: str) -> str:
        signals = 0
        if severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
            signals += 1
        if cvss is not None and cvss > 0:
            signals += 1
        if _has_cve(cve_id):
            signals += 1
        if signals >= 3:
            return "high"
        if signals >= 2:
            return "medium"
        return "low"

    def _recommendation(self, tier: PriorityTier, severity: SeverityLevel, cve_id: str) -> str:
        if tier == PriorityTier.CRITICAL:
            if _has_cve(cve_id):
                return "Immediate remediation required — actively exploitable vulnerability with known CVE"
            return "Immediate remediation required — critical severity finding"
        if tier == PriorityTier.HIGH:
            return "Prioritize remediation within current sprint cycle"
        if tier == PriorityTier.MEDIUM:
            return "Schedule remediation in next planning cycle"
        if tier == PriorityTier.LOW:
            return "Monitor and remediate during routine maintenance"
        return "No immediate action required"
