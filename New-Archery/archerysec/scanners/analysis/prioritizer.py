from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from scanners.base.result_models import SeverityLevel, VulnStatus
from .risk_scorer import RiskScorer, PriorityScore, PriorityTier


@dataclass
class PrioritizedFinding:
    title: str = ""
    severity: str = ""
    cvss_score: Optional[float] = None
    cve_id: str = ""
    scan_type: str = ""
    scanner_name: str = ""
    priority_score: float = 0.0
    priority_tier: str = ""
    confidence: str = ""
    recommendation: str = ""
    target: str = ""
    status: str = ""


class VulnerabilityPrioritizer:
    """Rule-based expert system for vulnerability prioritization."""

    def __init__(self):
        self.scorer = RiskScorer()

    def prioritize_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[PrioritizedFinding]:
        results = []
        for finding in findings:
            ps = self.scorer.score_finding(finding)
            results.append(PrioritizedFinding(
                title=finding.get("title", "Unknown"),
                severity=finding.get("severity", "info"),
                cvss_score=finding.get("cvss_score"),
                cve_id=finding.get("cve_id", ""),
                scan_type=finding.get("scan_type", ""),
                scanner_name=finding.get("scanner_name", ""),
                priority_score=ps.score,
                priority_tier=ps.tier.value,
                confidence=ps.confidence,
                recommendation=ps.recommendation,
                target=finding.get("url") or finding.get("host", ""),
                status=finding.get("vuln_status", "open"),
            ))
        results.sort(key=lambda r: r.priority_score, reverse=True)
        return results

    def prioritize_scan_summary(
        self,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        prioritized = self.prioritize_findings(findings)
        tier_counts = {t.value: 0 for t in PriorityTier}
        for p in prioritized:
            tier_counts[p.priority_tier] = tier_counts.get(p.priority_tier, 0) + 1
        top = [p for p in prioritized if p.priority_score >= 55][:10]
        return {
            "total_prioritized": len(prioritized),
            "tier_distribution": tier_counts,
            "top_priorities": [
                {
                    "title": p.title,
                    "score": p.priority_score,
                    "tier": p.priority_tier,
                    "recommendation": p.recommendation,
                    "target": p.target,
                    "scan_type": p.scan_type,
                }
                for p in top
            ],
        }
