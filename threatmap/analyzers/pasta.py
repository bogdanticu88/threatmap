"""PASTA (Process for Attack Simulation and Threat Analysis) threat analyzer."""
from typing import List, Optional

from threatmap.models.resource import Resource
from threatmap.models.threat import (
    PastaElement, PastaThreat, Severity, StrideCategory, Threat
)


# Classify resources by asset type
ASSET_CLASSIFICATION = {
    "data": ["s3_bucket", "dynamodb", "rds", "database", "storage", "ebs"],
    "identity": ["iam", "role", "policy", "user", "group", "secret"],
    "compute": ["instance", "lambda", "container", "pod", "ecs", "eks"],
    "network": ["security_group", "nacl", "route", "vpc", "subnet"],
}

# Threat actors relevant to cloud infrastructure
THREAT_ACTORS = {
    "internal": "Malicious insider or compromised internal user",
    "external": "External attacker or threat actor",
    "misconfiguration": "Accidental misconfiguration by operator",
    "supply_chain": "Compromised supply chain or dependency",
}

# PASTA attack scenarios
PASTA_SCENARIOS = {
    "data_exfiltration": "Attacker gains access to data asset and exfiltrates sensitive information",
    "privilege_escalation": "Attacker elevates permissions to access sensitive resources",
    "service_disruption": "Attacker disrupts service availability or performance",
    "configuration_tampering": "Attacker modifies resource configuration to enable attack",
    "lateral_movement": "Attacker moves from compromised resource to access other assets",
}


def _classify_asset_type(resource_type: str) -> str:
    """Classify resource as data, identity, compute, or network asset."""
    resource_lower = resource_type.lower()

    for asset_type, patterns in ASSET_CLASSIFICATION.items():
        if any(pattern in resource_lower for pattern in patterns):
            return asset_type

    return "infrastructure"


def _determine_threat_actor(resource: Resource) -> str:
    """Determine most likely threat actor based on resource characteristics."""
    resource_lower = resource.resource_type.lower()

    if "iam" in resource_lower or "role" in resource_lower:
        return "internal"
    elif resource.exposure == "public":
        return "external"
    else:
        return "external"


def _select_scenario(asset_type: str, resource: Resource) -> str:
    """Select relevant attack scenario based on asset type."""
    if asset_type == "data":
        return "data_exfiltration"
    elif asset_type == "identity":
        return "privilege_escalation"
    elif asset_type == "compute":
        return "lateral_movement"
    elif asset_type == "network":
        return "lateral_movement"
    else:
        return "configuration_tampering"


def analyze(resources: List[Resource]) -> List[Threat]:
    """
    Analyze infrastructure using PASTA framework.

    PASTA focuses on:
    - Assets (data, identity, compute, network resources)
    - Actors (who could attack: internal, external, misconfig)
    - Scenarios (how attacks could happen)
    - Vulnerabilities (misconfigurations)
    - Countermeasures (mitigation strategies)
    """
    threats: List[Threat] = []

    for resource in resources:
        asset_type = _classify_asset_type(resource.resource_type)
        threat_actor = _determine_threat_actor(resource)
        scenario = _select_scenario(asset_type, resource)

        pasta_threat = PastaThreat(
            element=PastaElement.SCENARIO,
            actor_type=threat_actor,
            asset_type=asset_type,
            scenario=scenario,
        )

        # Analyze data assets
        if asset_type == "data":
            # Check for encryption
            if resource.properties.get("encrypted") is False:
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                    severity=Severity.CRITICAL,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Data asset '{resource.name}' is unencrypted. Compromise could expose sensitive data.",
                    mitigation="Enable encryption at rest using provider-managed or CMK.",
                    trigger_property="encrypted",
                    pasta_threat=pasta_threat,
                ))

            # Check for versioning/recovery
            if resource.properties.get("versioning_enabled") is False:
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.TAMPERING,
                    severity=Severity.MEDIUM,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Data asset '{resource.name}' lacks versioning. Compromised data cannot be recovered.",
                    mitigation="Enable versioning to maintain recovery point objectives.",
                    trigger_property="versioning_enabled",
                    pasta_threat=pasta_threat,
                ))

        # Analyze identity assets
        if asset_type == "identity":
            # Check for overly permissive policies
            if resource.properties.get("inline_policy") or resource.properties.get("managed_policies"):
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                    severity=Severity.HIGH,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Identity asset '{resource.name}' may have excessive permissions. Review for least privilege.",
                    mitigation="Apply least-privilege principle; use condition-based policies.",
                    trigger_property="policy",
                    pasta_threat=pasta_threat,
                ))

        # Analyze compute assets
        if asset_type == "compute":
            if resource.exposure == "public":
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                    severity=Severity.CRITICAL,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Compute asset '{resource.name}' is publicly accessible. Attackers can target it for lateral movement to other resources.",
                    mitigation="Restrict access via security groups; use bastion hosts or SSM Session Manager.",
                    trigger_property="exposure",
                    pasta_threat=pasta_threat,
                ))

        # Analyze network assets
        if asset_type == "network":
            # Check for overly permissive ingress rules
            if resource.properties.get("ingress_rules"):
                rules = resource.properties.get("ingress_rules", [])
                for rule in rules if isinstance(rules, list) else []:
                    if rule.get("cidr_blocks") == ["0.0.0.0/0"]:
                        threats.append(Threat(
                            threat_id="",
                            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                            severity=Severity.HIGH,
                            resource_name=resource.name,
                            resource_type=resource.resource_type,
                            description=f"Network asset '{resource.name}' allows unrestricted ingress from any source.",
                            mitigation="Restrict ingress to required source IP ranges.",
                            trigger_property="ingress_rules",
                            pasta_threat=pasta_threat,
                        ))
                        break

    return threats
