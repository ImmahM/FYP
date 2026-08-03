from typing import Dict, Any, List, Optional
from .risk_scorer import PriorityTier


class ReportNarrativeGenerator:
    """Template-based natural language generation for security reports."""

    def executive_summary(
        self,
        total_findings: int,
        severity_counts: Dict[str, int],
        risk_tier: str,
        risk_score: float,
        scan_types: List[str],
        project_names: List[str],
        top_priorities: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        parts = []
        if total_findings == 0:
            return "No vulnerabilities were identified in the assessed scope."
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        medium = severity_counts.get("medium", 0)
        low = severity_counts.get("low", 0)
        scope = ", ".join(project_names) if project_names else "the selected scope"

        parts.append(
            f"This assessment identified {total_findings} unique "
            f"vulnerabilit{'y' if total_findings == 1 else 'ies'} across "
            f"{len(scan_types)} scan type{'s' if len(scan_types) != 1 else ''} "
            f"({', '.join(scan_types)}) in {scope}."
        )

        severity_parts = []
        if critical:
            severity_parts.append(f"{critical} critical")
        if high:
            severity_parts.append(f"{high} high")
        if medium:
            severity_parts.append(f"{medium} medium")
        if low:
            severity_parts.append(f"{low} low")
        if severity_parts:
            parts.append(
                "The severity distribution includes "
                + ", ".join(severity_parts)
                + " severity findings."
            )

        parts.append(
            f"The overall risk posture is assessed as {risk_tier} "
            f"(score: {risk_score:.1f}/100)."
        )

        if critical > 0 or high > 0:
            urgent = critical + high
            parts.append(
                f"A total of {urgent} finding{'s' if urgent != 1 else ''} "
                f"require{'s' if urgent == 1 else ''} immediate attention."
            )
        elif medium > 0:
            parts.append(
                f"{medium} medium-severity finding{'s' if medium != 1 else ''} "
                f"should be scheduled for remediation in the next planning cycle."
            )
        if top_priorities:
            top = top_priorities[:3]
            titles = [f"'{t['title']}' ({t['target']})" for t in top]
            parts.append(
                "Highest priority items: " + "; ".join(titles) + "."
            )
        return " ".join(parts)

    def section_summary(
        self,
        section_name: str,
        scan_type: str,
        total: int,
        critical: int,
        high: int,
        top_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        if total == 0:
            return f"No {scan_type} findings were identified."
        parts = [f"In the {section_name} section, {total} {scan_type} finding{'s' if total != 1 else ''} were identified."]
        if critical or high:
            parts.append(f"Of these, {critical} critical and {high} high-severity issues require attention.")
        if top_findings:
            names = [f["title"] for f in top_findings[:3]]
            parts.append(f"Key items: {'; '.join(names)}.")
        return " ".join(parts)

    def coverage_summary(
        self,
        scan_summaries: List[Dict[str, Any]],
    ) -> str:
        if not scan_summaries:
            return "No scan coverage data available."
        total_assets = sum(s.get("asset_count", 0) for s in scan_summaries)
        types = [s["label"] for s in scan_summaries]
        parts = [
            f"Scan coverage encompasses {total_assets} asset{'s' if total_assets != 1 else ''} "
            f"across {len(types)} scan categor{'y' if len(types) == 1 else 'ies'}: "
            f"{', '.join(types)}."
        ]
        inactive = [s["label"] for s in scan_summaries if not s.get("last_scan")]
        if inactive:
            parts.append(
                f"Note: {len(inactive)} scan categor{'y' if len(inactive) == 1 else 'ies'} "
                f"({', '.join(inactive)}) ha{'s' if len(inactive) == 1 else 've'} no recent scan data."
            )
        return " ".join(parts)

    def recommendation_summary(
        self,
        priority_targets: List[Dict[str, Any]],
        risk_tier: str,
    ) -> str:
        if not priority_targets:
            return "No specific remediation targets identified."
        if risk_tier in ("critical", "high"):
            top = priority_targets[0]
            return (
                f"Immediate remediation is recommended for '{top['name']}' "
                f"({top['type']}, score: {top['score']:.1f}), "
                f"which has the highest weighted risk in the assessed scope."
            )
        return (
            f"Remediation efforts should focus on the {len(priority_targets)} "
            f"priority targets listed below, ordered by weighted risk score."
        )
