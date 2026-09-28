"""Vulnerability correlation engine.

Deduplicates, merges, and correlates vulnerability records from multiple
sources into unified findings. Does NOT simply concatenate results.

Correlation strategy:
  1. Group records by CVE ID (primary key)
  2. Merge CVSS, EPSS, KEV, exploit refs from all sources
  3. Deduplicate by (CVE, GHSA, OSV) identifiers
  4. Score confidence based on number of corroborating sources
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from vulnscanner.core.logging import get_logger
from vulnscanner.core.models import (
    CVSSScore,
    EPSSScore,
    KEVEntry,
    ExploitReference,
    VulnerabilityRecord,
)

logger = get_logger(__name__)


class CorrelationEngine:
    """Merges vulnerability data from multiple sources into deduplicated records."""

    def correlate(
        self, records: list[VulnerabilityRecord]
    ) -> list[VulnerabilityRecord]:
        """Correlate and deduplicate vulnerability records.

        Args:
            records: Raw records from multiple sources.

        Returns:
            Deduplicated, enriched vulnerability records.
        """
        if not records:
            return []

        # Group by primary identifiers
        groups: dict[str, list[VulnerabilityRecord]] = defaultdict(list)

        for record in records:
            key = self._group_key(record)
            groups[key].append(record)

        # Merge each group
        merged: list[VulnerabilityRecord] = []
        for key, group in groups.items():
            if len(group) == 1:
                merged.append(group[0])
            else:
                merged.append(self._merge_group(group))

        logger.info(
            "correlation_complete",
            input_records=len(records),
            output_records=len(merged),
            groups=len(groups),
        )

        return merged

    def _group_key(self, record: VulnerabilityRecord) -> str:
        """Generate a grouping key for deduplication."""
        if record.cve_id:
            return f"CVE:{record.cve_id}"
        if record.ghsa_id:
            return f"GHSA:{record.ghsa_id}"
        if record.osv_id:
            return f"OSV:{record.osv_id}"
        return f"UUID:{record.id}"

    def _merge_group(
        self, group: list[VulnerabilityRecord]
    ) -> VulnerabilityRecord:
        """Merge multiple records for the same vulnerability."""
        base = group[0].model_copy()

        all_sources: list[str] = []
        all_confidence: dict[str, float] = {}
        evidence: list[str] = []

        for record in group:
            # Merge identifiers
            if record.cve_id and not base.cve_id:
                base.cve_id = record.cve_id
            if record.ghsa_id and not base.ghsa_id:
                base.ghsa_id = record.ghsa_id
            if record.osv_id and not base.osv_id:
                base.osv_id = record.osv_id

            # Merge advisory IDs
            for aid in record.vendor_advisory_ids:
                if aid not in base.vendor_advisory_ids:
                    base.vendor_advisory_ids.append(aid)

            # Use longest description
            if record.description and len(record.description) > len(base.description or ""):
                base.description = record.description

            # Merge CVSS — keep all unique scores
            existing_vectors = {s.vector_string for s in base.cvss_scores if s.vector_string}
            for score in record.cvss_scores:
                if score.vector_string not in existing_vectors:
                    base.cvss_scores.append(score)
                    existing_vectors.add(score.vector_string)

            # EPSS — take the most recent
            if record.epss and (not base.epss or
                                (record.epss.date and base.epss.date and
                                 record.epss.date > base.epss.date)):
                base.epss = record.epss

            # KEV — if any source says it's KEV, it's KEV
            if record.kev:
                base.kev = record.kev

            # Exploits
            existing_exploits = {(e.source, e.id) for e in base.exploits}
            for exploit in record.exploits:
                if (exploit.source, exploit.id) not in existing_exploits:
                    base.exploits.append(exploit)

            if record.exploit_available:
                base.exploit_available = True

            # Versions
            for v in record.affected_versions:
                if v not in base.affected_versions:
                    base.affected_versions.append(v)
            for v in record.fixed_versions:
                if v not in base.fixed_versions:
                    base.fixed_versions.append(v)

            # CPEs
            for cpe in record.affected_cpes:
                if cpe not in base.affected_cpes:
                    base.affected_cpes.append(cpe)

            # References
            for ref in record.references:
                if ref and ref not in base.references:
                    base.references.append(ref)

            # Source tracking
            all_sources.extend(record.sources)
            all_confidence.update(record.source_confidence)
            evidence.append(f"Corroborated by {', '.join(record.sources)}")

            # Dates — use earliest published, latest modified
            if record.published:
                if not base.published or record.published < base.published:
                    base.published = record.published
            if record.last_modified:
                if not base.last_modified or record.last_modified > base.last_modified:
                    base.last_modified = record.last_modified

        # Update sources
        base.sources = list(set(all_sources))
        base.source_confidence = all_confidence
        base.correlation_evidence = evidence

        # Confidence boost: more sources = higher confidence
        source_count = len(base.sources)
        if source_count >= 4:
            base.confidence = min(0.98, max(base.confidence, 0.95))
        elif source_count >= 3:
            base.confidence = min(0.95, max(base.confidence, 0.90))
        elif source_count >= 2:
            base.confidence = min(0.90, max(base.confidence, 0.85))

        return base
