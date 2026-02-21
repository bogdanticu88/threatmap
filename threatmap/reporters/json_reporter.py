"""
JSON threat model report generator.
"""
import json
from datetime import datetime
from typing import List

from threatmap import __version__
from threatmap.models.resource import Resource
from threatmap.models.threat import Severity, Threat


def _count_by_severity(threats: List[Threat]) -> dict:
    counts = {s.value: 0 for s in Severity}
    for t in threats:
        counts[t.severity.value] += 1
    return counts


def build_report(
    resources: List[Resource], threats: List[Threat], source_path: str
) -> str:
    report = {
        "meta": {
            "generated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": source_path,
            "tool": "threatmap",
            "version": __version__,
        },
        "summary": _count_by_severity(threats),
        "resources": [
            {
                "name": r.name,
                "resource_type": r.resource_type,
                "provider": r.provider,
                "source_format": r.source_format,
                "source_file": r.source_file,
                "exposure": r.exposure,
                "relationships": r.relationships,
            }
            for r in resources
        ],
        "threats": [t.to_dict() for t in threats],
    }
    return json.dumps(report, indent=2)
