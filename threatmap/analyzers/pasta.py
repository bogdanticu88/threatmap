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
    "compute": ["instance", "lambda", "container", "pod", "ecs", "eks", "deployment"],
    "network": ["security_group", "nacl", "route", "vpc", "subnet", "namespace"],
    "infrastructure": ["trail", "cloudtrail", "waf", "shield", "config", "guardduty"],
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

    if any(x in resource_lower for x in ["container", "image", "pod", "ecs", "eks", "deployment"]):
        return "supply_chain"
    elif any(x in resource_lower for x in ["iam", "role", "policy", "user", "group"]):
        return "internal"
    elif resource.exposure == "public":
        return "external"
    else:
        return "misconfiguration"


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
    elif asset_type == "infrastructure":
        return "service_disruption"
    else:
        return "configuration_tampering"


def analyze(resources: List[Resource]) -> List[Threat]:
    """
    Analyze infrastructure using PASTA framework.

    PASTA focuses on:
    - Assets (data, identity, compute, network resources)
    - Actors (who could attack: internal, external, misconfig, supply_chain)
    - Scenarios (how attacks could happen)
    - Vulnerabilities (misconfigurations)
    - Countermeasures (mitigation strategies)
    """
    threats: List[Threat] = []

    for resource in resources:
        asset_type = _classify_asset_type(resource.resource_type)
        threat_actor = _determine_threat_actor(resource)
        scenario = _select_scenario(asset_type, resource)
        resource_lower = resource.resource_type.lower()

        # Rule 1: Data asset - unencrypted
        if asset_type == "data":
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
                    pasta_threat=PastaThreat(
                        element=PastaElement.VULNERABILITY,
                        actor_type=threat_actor,
                        asset_type=asset_type,
                        scenario="data_exfiltration",
                    ),
                ))

            # Rule 2: Data asset - no versioning
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
                    pasta_threat=PastaThreat(
                        element=PastaElement.COUNTERMEASURE,
                        actor_type=threat_actor,
                        asset_type=asset_type,
                        scenario="data_exfiltration",
                    ),
                ))

            # Rule 6: Public S3 bucket (data asset specific)
            if resource.exposure == "public" or (
                "s3" in resource_lower and resource.properties.get("public_access_block") is None
            ):
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                    severity=Severity.CRITICAL,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Data asset '{resource.name}' is a public bucket. Unauthenticated users can read all stored objects.",
                    mitigation="Block all public access via S3 Block Public Access; remove any public bucket policies.",
                    trigger_property="public_access_block",
                    pasta_threat=PastaThreat(
                        element=PastaElement.ASSET,
                        actor_type="external",
                        asset_type="data",
                        scenario="data_exfiltration",
                    ),
                ))

        # Rule 3: Identity assets - overly permissive policies
        if asset_type == "identity":
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
                    pasta_threat=PastaThreat(
                        element=PastaElement.VULNERABILITY,
                        actor_type=threat_actor,
                        asset_type="identity",
                        scenario="privilege_escalation",
                    ),
                ))

            # Rule 7: Identity asset - no MFA
            if resource.properties.get("mfa_enabled") is False:
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.SPOOFING,
                    severity=Severity.HIGH,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Identity asset '{resource.name}' does not enforce MFA. Password compromise is sufficient for full access.",
                    mitigation="Require MFA for all human identities; use IAM condition 'aws:MultiFactorAuthPresent'.",
                    trigger_property="mfa_enabled",
                    pasta_threat=PastaThreat(
                        element=PastaElement.VULNERABILITY,
                        actor_type="external",
                        asset_type="identity",
                        scenario="privilege_escalation",
                    ),
                ))

            # Rule 12: Identity asset - wildcard IAM policy
            if resource.properties.get("policy.wildcard") is True:
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                    severity=Severity.CRITICAL,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Identity asset '{resource.name}' has a wildcard (*) IAM policy granting unrestricted access.",
                    mitigation="Replace wildcard actions and resources with the minimum necessary permissions.",
                    trigger_property="policy.wildcard",
                    pasta_threat=PastaThreat(
                        element=PastaElement.ACTOR,
                        actor_type="internal",
                        asset_type="identity",
                        scenario="privilege_escalation",
                    ),
                ))

        # Rule 4: Compute assets - public exposure
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
                    pasta_threat=PastaThreat(
                        element=PastaElement.ASSET,
                        actor_type="external",
                        asset_type="compute",
                        scenario="lateral_movement",
                    ),
                ))

            # Rule 9: Compute asset - container running as root
            if resource.properties.get("run_as_user") == 0 or resource.properties.get("run_as_non_root") is False:
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                    severity=Severity.HIGH,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Compute asset '{resource.name}' runs containers as root. Container escape yields host-level privilege.",
                    mitigation="Set runAsNonRoot: true and specify a non-zero UID in the pod security context.",
                    trigger_property="run_as_user",
                    pasta_threat=PastaThreat(
                        element=PastaElement.VULNERABILITY,
                        actor_type=threat_actor,
                        asset_type="compute",
                        scenario="privilege_escalation",
                    ),
                ))

            # Rule 10: Compute asset - image tag :latest (supply chain)
            image = resource.properties.get("image", "")
            if image and image.endswith(":latest"):
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.TAMPERING,
                    severity=Severity.MEDIUM,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Compute asset '{resource.name}' uses ':latest' image tag. Supply chain compromise can silently replace the image.",
                    mitigation="Pin container images to specific digest hashes; use a trusted image registry with signing.",
                    trigger_property="image_tag",
                    pasta_threat=PastaThreat(
                        element=PastaElement.ACTOR,
                        actor_type="supply_chain",
                        asset_type="compute",
                        scenario="configuration_tampering",
                    ),
                ))

        # Rule 5: Network assets - unrestricted ingress
        if asset_type == "network":
            if resource.properties.get("ingress_rules"):
                rules = resource.properties.get("ingress_rules", [])
                for rule in (rules if isinstance(rules, list) else []):
                    if isinstance(rule, dict) and rule.get("cidr_blocks") == ["0.0.0.0/0"]:
                        threats.append(Threat(
                            threat_id="",
                            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                            severity=Severity.HIGH,
                            resource_name=resource.name,
                            resource_type=resource.resource_type,
                            description=f"Network asset '{resource.name}' allows unrestricted ingress from any source.",
                            mitigation="Restrict ingress to required source IP ranges.",
                            trigger_property="ingress_rules",
                            pasta_threat=PastaThreat(
                                element=PastaElement.VULNERABILITY,
                                actor_type=threat_actor,
                                asset_type="network",
                                scenario="lateral_movement",
                            ),
                        ))
                        break

            # Rule 11: Network asset - no Kubernetes NetworkPolicy
            if resource.resource_type == "Namespace" and resource.source_format == "kubernetes":
                if resource.properties.get("NetworkPolicy.missing") is True or resource.properties.get("has_network_policy") is not True:
                    threats.append(Threat(
                        threat_id="",
                        stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                        severity=Severity.HIGH,
                        resource_name=resource.name,
                        resource_type=resource.resource_type,
                        description=f"Kubernetes namespace '{resource.name}' lacks a NetworkPolicy, allowing unrestricted pod-to-pod traffic.",
                        mitigation="Apply a default-deny NetworkPolicy; explicitly allow only required ingress/egress.",
                        trigger_property="NetworkPolicy.missing",
                        pasta_threat=PastaThreat(
                            element=PastaElement.COUNTERMEASURE,
                            actor_type="external",
                            asset_type="network",
                            scenario="lateral_movement",
                        ),
                    ))

        # Rule 8: Infrastructure assets - no logging
        if asset_type == "infrastructure":
            if resource.properties.get("enable_log_file_validation") is False or resource.properties.get("logging_enabled") is False:
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.REPUDIATION,
                    severity=Severity.MEDIUM,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Infrastructure resource '{resource.name}' has logging disabled. Attackers can operate without audit trail.",
                    mitigation="Enable logging and retain logs for at least 90 days.",
                    trigger_property="logging_enabled",
                    pasta_threat=PastaThreat(
                        element=PastaElement.COUNTERMEASURE,
                        actor_type="misconfiguration",
                        asset_type="infrastructure",
                        scenario="service_disruption",
                    ),
                ))

    return threats


# Module-level rule count for dynamic API responses
RULE_COUNT = 12
