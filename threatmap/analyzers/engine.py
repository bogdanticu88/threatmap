from typing import List

from threatmap.analyzers import aws, azure, gcp, kubernetes
from threatmap.models.resource import Resource
from threatmap.models.threat import Threat

ANALYZERS = [aws.analyze, azure.analyze, gcp.analyze, kubernetes.analyze]

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def run(resources: List[Resource]) -> List[Threat]:
    """
    Run all analyzers, deduplicate by (stride_category, resource_name, trigger_property),
    sort by severity, and assign sequential threat IDs.
    """
    all_threats: List[Threat] = []
    seen = set()

    for fn in ANALYZERS:
        for t in fn(resources):
            key = (t.stride_category, t.resource_name, t.trigger_property)
            if key not in seen:
                seen.add(key)
                all_threats.append(t)

    all_threats.sort(
        key=lambda t: (
            _SEVERITY_ORDER.get(t.severity.value, 99),
            t.resource_name,
        )
    )

    for i, t in enumerate(all_threats, 1):
        t.threat_id = f"T-{i:03d}"

    return all_threats
