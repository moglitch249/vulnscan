"""Transparent risk scoring engine.

Every calculated score explains exactly how it was computed.
No "AI severity" — only verifiable, evidence-based factors.
"""

from __future__ import annotations

from uuid import UUID

from vulnscanner.core.logging import get_logger
from vulnscanner.core.models import (
    RiskAssessment,
    RiskFactor,
    VulnerabilityRecord,
)

logger = get_logger(__name__)

# Factor weights (must sum to ~1.0 for normalization)
_WEIGHTS = {
    "cvss": 0.30,
    "epss": 0.20,
    "kev": 0.20,
    "exploit": 0.15,
    "confidence": 0.10,
    "age": 0.05,
}


class RiskEngine:
    """Transparent, explainable risk scoring."""

    def assess(self, vuln: VulnerabilityRecord) -> RiskAssessment:
        """Calculate risk score for a vulnerability.

        Returns RiskAssessment with full breakdown of factors.
        """
        factors: list[RiskFactor] = []
        total = 0.0

        # 1. CVSS Score (0-10 → 0-100)
        cvss_val = 0.0
        if vuln.max_cvss_score is not None:
            cvss_val = vuln.max_cvss_score * 10.0
        factors.append(RiskFactor(
            name="CVSS Base Score",
            value=cvss_val,
            weight=_WEIGHTS["cvss"],
            description=f"Highest CVSS score: {vuln.max_cvss_score or 'N/A'}/10",
            evidence=f"From: {', '.join(s.source or '?' for s in vuln.cvss_scores)}" if vuln.cvss_scores else "No CVSS data",
        ))
        total += cvss_val * _WEIGHTS["cvss"]

        # 2. EPSS Score (0-1 → 0-100)
        epss_val = 0.0
        if vuln.epss:
            epss_val = vuln.epss.score * 100.0
        factors.append(RiskFactor(
            name="EPSS Probability",
            value=epss_val,
            weight=_WEIGHTS["epss"],
            description=f"EPSS exploit probability: {vuln.epss.score:.4f}" if vuln.epss else "No EPSS data",
            evidence=f"Percentile: {vuln.epss.percentile:.2%}" if vuln.epss else None,
        ))
        total += epss_val * _WEIGHTS["epss"]

        # 3. CISA KEV (binary: 0 or 100)
        kev_val = 100.0 if vuln.kev else 0.0
        kev_desc = "IN CISA KEV catalog — known exploited in the wild" if vuln.kev else "Not in KEV"
        factors.append(RiskFactor(
            name="CISA KEV Status",
            value=kev_val,
            weight=_WEIGHTS["kev"],
            description=kev_desc,
            evidence=f"Added: {vuln.kev.date_added}" if vuln.kev and vuln.kev.date_added else None,
        ))
        total += kev_val * _WEIGHTS["kev"]

        # 4. Public exploit availability (binary: 0 or 100)
        exploit_val = 100.0 if vuln.exploit_available or vuln.exploits else 0.0
        factors.append(RiskFactor(
            name="Exploit Availability",
            value=exploit_val,
            weight=_WEIGHTS["exploit"],
            description=f"{len(vuln.exploits)} public exploit(s)" if vuln.exploits else "No public exploits known",
            evidence=", ".join(e.source for e in vuln.exploits[:5]) if vuln.exploits else None,
        ))
        total += exploit_val * _WEIGHTS["exploit"]

        # 5. Fingerprint / Source confidence (0-1 → 0-100)
        conf_val = vuln.confidence * 100.0
        factors.append(RiskFactor(
            name="Detection Confidence",
            value=conf_val,
            weight=_WEIGHTS["confidence"],
            description=f"Confidence: {vuln.confidence:.0%} from {len(vuln.sources)} source(s)",
            evidence=f"Sources: {', '.join(vuln.sources)}",
        ))
        total += conf_val * _WEIGHTS["confidence"]

        # 6. Vulnerability age (older = slightly higher risk if still open)
        age_val = 50.0  # neutral default
        if vuln.published:
            from datetime import datetime
            age_days = (datetime.utcnow() - vuln.published).days
            if age_days > 365:
                age_val = 80.0
                age_desc = f"Published {age_days} days ago — long-standing vulnerability"
            elif age_days > 90:
                age_val = 60.0
                age_desc = f"Published {age_days} days ago"
            elif age_days < 30:
                age_val = 70.0  # new vulns are hot targets
                age_desc = f"Published {age_days} days ago — recently disclosed"
            else:
                age_val = 50.0
                age_desc = f"Published {age_days} days ago"
        else:
            age_desc = "Publication date unknown"

        factors.append(RiskFactor(
            name="Vulnerability Age",
            value=age_val,
            weight=_WEIGHTS["age"],
            description=age_desc,
        ))
        total += age_val * _WEIGHTS["age"]

        # Clamp to 0-100
        total = max(0.0, min(100.0, total))

        # Build explanation
        explanation_parts = [
            f"Risk Score: {total:.1f}/100",
            "Calculated from:",
        ]
        for f in factors:
            explanation_parts.append(
                f"  • {f.name}: {f.value:.1f} × {f.weight:.0%} = {f.value * f.weight:.1f}"
            )

        return RiskAssessment(
            vulnerability_id=vuln.id,
            risk_score=total,
            factors=factors,
            explanation="\n".join(explanation_parts),
        )

    def assess_batch(
        self, vulns: list[VulnerabilityRecord]
    ) -> list[RiskAssessment]:
        """Assess risk for multiple vulnerabilities."""
        return [self.assess(v) for v in vulns]
