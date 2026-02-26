import os
from typing import Dict, List, Optional

import yaml

from threatmap.analyzers import aws, azure, gcp, kubernetes
from threatmap.models.resource import Resource
from threatmap.models.threat import Severity, StrideCategory, Threat

ANALYZERS = [aws.analyze, azure.analyze, gcp.analyze, kubernetes.analyze]

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _run_custom_rules(resources: List[Resource]) -> List[Threat]:
    """Load and run rules from a 'threatmap_rules.yaml' if it exists."""
    custom_threats = []
    rule_file = "threatmap_rules.yaml"
    if not os.path.exists(rule_file):
        return []

    try:
        with open(rule_file, "r") as f:
            config = yaml.safe_load(f)
            rules = config.get("rules", [])
    except Exception:
        return []

    for rule in rules:
        target_type = rule.get("resource_type")
        prop = rule.get("property")
        expected = rule.get("expected")
        
        for r in resources:
            if r.resource_type == target_type or target_type == "*":
                val = r.properties.get(prop)
                if val != expected:
                    custom_threats.append(Threat(
                        threat_id="",
                        stride_category=StrideCategory(rule.get("stride", "Information Disclosure")),
                        severity=Severity(rule.get("severity", "MEDIUM")),
                        resource_name=r.name,
                        resource_type=r.resource_type,
                        description=rule.get("description", f"Custom rule violation for {r.name}"),
                        mitigation=rule.get("mitigation", "Follow internal security standards."),
                        trigger_property=prop,
                        remediation=rule.get("remediation")
                    ))
    return custom_threats


def _analyze_attack_paths(resources: List[Resource]) -> List[Threat]:
    """
    Graph-based analysis: trace paths from Internet to sensitive data.
    Identifies 'chained' threats (Elevation of Privilege).
    """
    threats = []
    resource_map = {r.name: r for r in resources}
    
    # Identify internet-exposed compute
    exposed_compute = [
        r for r in resources 
        if r.exposure == "public" and any(k in r.resource_type for k in ("instance", "lambda", "container", "Pod"))
    ]
    
    for compute in exposed_compute:
        for rel in compute.relationships:
            # rel might be 'aws_s3_bucket.my_data'
            target_name = rel.split(".")[-1]
            target = resource_map.get(target_name)
            
            if target and any(k in target.resource_type for k in ("s3", "storage", "db", "sql")):
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                    severity=Severity.HIGH,
                    resource_name=compute.name,
                    resource_type=compute.resource_type,
                    description=f"Exposed compute '{compute.name}' can access data resource '{target.name}'. A compromise of this compute resource provides a direct path to sensitive data.",
                    mitigation=f"Ensure least-privilege IAM roles for '{compute.name}' and use VPC endpoints for data access.",
                    trigger_property="relationships",
                    remediation=f"Restrict '{compute.name}' access to only required actions on '{target.name}'."
                ))
                
    return threats


def run(resources: List[Resource]) -> List[Threat]:
    """
    Run all analyzers, custom rules, and graph analysis.
    Assign sequential threat IDs and sort by severity.
    """
    all_threats: List[Threat] = []
    seen = set()

    # 1. Built-in Analyzers
    for fn in ANALYZERS:
        for t in fn(resources):
            key = (t.stride_category, t.resource_name, t.trigger_property)
            if key not in seen:
                seen.add(key)
                all_threats.append(t)

    # 2. Custom Rules
    for t in _run_custom_rules(resources):
        key = (t.stride_category, t.resource_name, t.trigger_property)
        if key not in seen:
            seen.add(key)
            all_threats.append(t)

    # 3. Graph/Attack Path Analysis
    for t in _analyze_attack_paths(resources):
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
