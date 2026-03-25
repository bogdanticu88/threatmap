"""MITRE ATT&CK threat analyzer for infrastructure code."""
from typing import Dict, List, Optional

from threatmap.models.resource import Resource
from threatmap.models.threat import (
    MitreCategory, MitreTtp, Severity, StrideCategory, Threat
)


# Mapping of STRIDE to MITRE ATT&CK tactics
STRIDE_TO_MITRE_TACTICS: Dict[str, List[MitreCategory]] = {
    StrideCategory.SPOOFING.value: [
        MitreCategory.INITIAL_ACCESS,
        MitreCategory.CREDENTIAL_ACCESS,
    ],
    StrideCategory.TAMPERING.value: [
        MitreCategory.EXECUTION,
        MitreCategory.PERSISTENCE,
        MitreCategory.DEFENSE_EVASION,
    ],
    StrideCategory.REPUDIATION.value: [
        MitreCategory.COMMAND_AND_CONTROL,
        MitreCategory.EXFILTRATION,
    ],
    StrideCategory.INFORMATION_DISCLOSURE.value: [
        MitreCategory.COLLECTION,
        MitreCategory.EXFILTRATION,
    ],
    StrideCategory.DENIAL_OF_SERVICE.value: [
        MitreCategory.IMPACT,
    ],
    StrideCategory.ELEVATION_OF_PRIVILEGE.value: [
        MitreCategory.PRIVILEGE_ESCALATION,
        MitreCategory.LATERAL_MOVEMENT,
    ],
}

# MITRE ATT&CK techniques for cloud infrastructure
MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "IAM": {
        "T1556": "Modify Authentication Process",
        "T1578": "Modify Cloud Compute Infrastructure",
        "T1562": "Impair Defenses",
    },
    "Storage": {
        "T1530": "Data from Cloud Storage",
        "T1537": "Transfer Data to Cloud Account",
    },
    "Network": {
        "T1046": "Network Service Discovery",
        "T1087": "Account Discovery",
        "T1526": "Cloud Service Discovery",
    },
    "Compute": {
        "T1199": "Trusted Relationship",
        "T1570": "Lateral Tool Transfer",
        "T1021": "Remote Services",
    },
    "Data": {
        "T1005": "Data from Local System",
        "T1537": "Transfer Data to Cloud Account",
        "T1020": "Automated Exfiltration",
    },
}

# Technique ID to (Tactic, Name) mapping for resource-aware TTP selection
TECHNIQUE_DETAILS: Dict[str, tuple] = {
    "T1556": (MitreCategory.CREDENTIAL_ACCESS,    "Modify Authentication Process"),
    "T1098": (MitreCategory.PERSISTENCE,          "Account Manipulation"),
    "T1078": (MitreCategory.PRIVILEGE_ESCALATION, "Valid Accounts"),
    "T1530": (MitreCategory.COLLECTION,           "Data from Cloud Storage"),
    "T1537": (MitreCategory.EXFILTRATION,         "Transfer Data to Cloud Account"),
    "T1046": (MitreCategory.DISCOVERY,            "Network Service Discovery"),
    "T1526": (MitreCategory.DISCOVERY,            "Cloud Service Discovery"),
    "T1005": (MitreCategory.COLLECTION,           "Data from Local System"),
    "T1562": (MitreCategory.DEFENSE_EVASION,      "Impair Defenses"),
    "T1611": (MitreCategory.PRIVILEGE_ESCALATION, "Escape to Host"),
    "T1021": (MitreCategory.LATERAL_MOVEMENT,     "Remote Services"),
    "T1087": (MitreCategory.DISCOVERY,            "Account Discovery"),
    "T1570": (MitreCategory.LATERAL_MOVEMENT,     "Lateral Tool Transfer"),
    "T1648": (MitreCategory.EXECUTION,            "Serverless Execution"),
}


def _get_mitre_ttps_for_stride(stride_category: str) -> List[MitreTtp]:
    """Get MITRE ATT&CK TTPs for a STRIDE category."""
    tactics = STRIDE_TO_MITRE_TACTICS.get(stride_category, [])
    ttps = []

    for tactic in tactics:
        # Select appropriate technique based on tactic
        techniques = {
            MitreCategory.INITIAL_ACCESS: ("T1199", "Trusted Relationship"),
            MitreCategory.CREDENTIAL_ACCESS: ("T1110", "Brute Force"),
            MitreCategory.EXECUTION: ("T1648", "Serverless Execution"),
            MitreCategory.PERSISTENCE: ("T1098", "Account Manipulation"),
            MitreCategory.DEFENSE_EVASION: ("T1562", "Impair Defenses"),
            MitreCategory.PRIVILEGE_ESCALATION: ("T1078", "Valid Accounts"),
            MitreCategory.COLLECTION: ("T1005", "Data from Local System"),
            MitreCategory.COMMAND_AND_CONTROL: ("T1071", "Application Layer Protocol"),
            MitreCategory.EXFILTRATION: ("T1537", "Transfer Data to Cloud Account"),
            MitreCategory.IMPACT: ("T1531", "Account Access Removal"),
            MitreCategory.LATERAL_MOVEMENT: ("T1570", "Lateral Tool Transfer"),
        }.get(tactic, ("T0000", "Unknown Technique"))

        ttps.append(MitreTtp(
            tactic=tactic,
            technique_id=techniques[0],
            technique_name=techniques[1]
        ))

    return ttps


def _get_techniques_for_resource(resource_type: str) -> List[str]:
    """Get relevant MITRE techniques based on resource type."""
    resource_lower = resource_type.lower()

    if any(x in resource_lower for x in ["iam", "role", "policy", "user"]):
        return ["T1556", "T1098", "T1078"]
    elif any(x in resource_lower for x in ["s3", "storage", "bucket"]):
        return ["T1530", "T1537"]
    elif any(x in resource_lower for x in ["security_group", "network", "acl"]):
        return ["T1046", "T1087", "T1526"]
    elif any(x in resource_lower for x in ["instance", "lambda", "container"]):
        return ["T1570", "T1021", "T1648"]
    elif any(x in resource_lower for x in ["database", "rds", "dynamodb"]):
        return ["T1005", "T1537"]

    return []


def analyze(resources: List[Resource]) -> List[Threat]:
    """
    Analyze infrastructure for MITRE ATT&CK techniques.

    This analyzer maps STRIDE threats to MITRE ATT&CK framework,
    providing tactics and techniques relevant to cloud infrastructure threats.
    """
    threats: List[Threat] = []

    for resource in resources:
        resource_lower = resource.resource_type.lower()

        # Rule 1: IAM role with no trust policy
        if "iam" in resource_lower and "role" in resource_lower:
            if resource.properties.get("assume_role_policy_document") is None:
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                    severity=Severity.HIGH,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description="IAM role lacks explicit trust relationship definition. Attackers could assume this role if trust is misconfigured.",
                    mitigation="Define explicit trust relationships and use least-privilege principles.",
                    trigger_property="assume_role_policy_document",
                    mitre_ttps=_get_mitre_ttps_for_stride(StrideCategory.ELEVATION_OF_PRIVILEGE.value),
                ))

        # Rule 2: IAM resource with no MFA enforcement
        if "iam" in resource_lower or "user" in resource_lower:
            if resource.properties.get("mfa_enabled") is False:
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.SPOOFING,
                    severity=Severity.HIGH,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"IAM resource '{resource.name}' does not enforce MFA. Stolen credentials allow direct account access without second factor.",
                    mitigation="Enable MFA enforcement via IAM policy conditions (aws:MultiFactorAuthPresent).",
                    trigger_property="mfa_enabled",
                    mitre_ttps=[MitreTtp(
                        tactic=MitreCategory.CREDENTIAL_ACCESS,
                        technique_id="T1556",
                        technique_name="Modify Authentication Process"
                    )],
                ))

        # Rule 3: IAM resource with wildcard policy
        if "iam" in resource_lower or "policy" in resource_lower:
            if resource.properties.get("policy.wildcard") is True:
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                    severity=Severity.HIGH,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"IAM resource '{resource.name}' has a wildcard (*) policy. Compromised credentials grant unrestricted access.",
                    mitigation="Replace wildcard policies with resource-scoped, action-scoped least-privilege policies.",
                    trigger_property="policy.wildcard",
                    mitre_ttps=[MitreTtp(
                        tactic=MitreCategory.PERSISTENCE,
                        technique_id="T1098",
                        technique_name="Account Manipulation"
                    )],
                ))

        # Rule 4: Security group with open ingress to 0.0.0.0/0
        if "security_group" in resource_lower:
            ingress_rules = resource.properties.get("ingress_rules", [])
            if any(
                isinstance(rule, dict) and rule.get("cidr_blocks") == ["0.0.0.0/0"]
                for rule in (ingress_rules if isinstance(ingress_rules, list) else [])
            ):
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                    severity=Severity.HIGH,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Security group '{resource.name}' allows unrestricted ingress (0.0.0.0/0). Attackers can perform network service discovery.",
                    mitigation="Restrict ingress rules to required source CIDR ranges and ports.",
                    trigger_property="ingress_rules",
                    mitre_ttps=[MitreTtp(
                        tactic=MitreCategory.DISCOVERY,
                        technique_id="T1046",
                        technique_name="Network Service Discovery"
                    )],
                ))

        # Rule 5: Public S3 bucket (EXFILTRATION path)
        if "s3_bucket" in resource_lower or ("bucket" in resource_lower and "s3" in resource.resource_type.lower()):
            if resource.exposure == "public" or resource.properties.get("public_access_block") is None:
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                    severity=Severity.CRITICAL,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"S3 bucket '{resource.name}' is publicly accessible or has no public access block. Data can be exfiltrated by external actors.",
                    mitigation="Enable S3 Block Public Access settings and apply restrictive bucket policy.",
                    trigger_property="public_access_block",
                    mitre_ttps=[MitreTtp(
                        tactic=MitreCategory.EXFILTRATION,
                        technique_id="T1530",
                        technique_name="Data from Cloud Storage"
                    )],
                ))

        # Rule 6: Resource with no logging/audit trail
        if resource.properties.get("enable_log_file_validation") is False or resource.properties.get("logging_enabled") is False:
            threats.append(Threat(
                threat_id="",
                stride_category=StrideCategory.REPUDIATION,
                severity=Severity.MEDIUM,
                resource_name=resource.name,
                resource_type=resource.resource_type,
                description=f"Resource '{resource.name}' has logging disabled. Attackers can operate without audit trail.",
                mitigation="Enable logging and log file validation; ship logs to a separate, restricted account.",
                trigger_property="logging_enabled",
                mitre_ttps=[MitreTtp(
                    tactic=MitreCategory.DEFENSE_EVASION,
                    technique_id="T1562",
                    technique_name="Impair Defenses"
                )],
            ))

        # Rule 7: Container running as root
        if resource.source_format == "kubernetes" or "container" in resource_lower or "pod" in resource_lower:
            if resource.properties.get("run_as_user") == 0 or resource.properties.get("run_as_non_root") is False:
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                    severity=Severity.HIGH,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Container in '{resource.name}' runs as root (UID 0). A container escape grants host root access.",
                    mitigation="Set runAsUser to a non-zero UID; set runAsNonRoot: true in the security context.",
                    trigger_property="run_as_user",
                    mitre_ttps=[MitreTtp(
                        tactic=MitreCategory.PRIVILEGE_ESCALATION,
                        technique_id="T1611",
                        technique_name="Escape to Host"
                    )],
                ))

        # Rule 8: Unencrypted storage/database
        if any(x in resource_lower for x in ["ebs", "storage", "disk", "volume", "database", "rds", "dynamodb"]):
            if resource.properties.get("encrypted") is False:
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                    severity=Severity.HIGH,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Storage resource '{resource.name}' is unencrypted. Physical media access or snapshot theft exposes data directly.",
                    mitigation="Enable encryption at rest with a provider-managed or customer-managed key.",
                    trigger_property="encrypted",
                    mitre_ttps=[MitreTtp(
                        tactic=MitreCategory.COLLECTION,
                        technique_id="T1005",
                        technique_name="Data from Local System"
                    )],
                ))

        # Rule 9: Public exposure via reconnaissance
        if resource.exposure == "public":
            techniques = _get_techniques_for_resource(resource.resource_type)
            threat_ttps = [
                MitreTtp(
                    tactic=MitreCategory.RECONNAISSANCE,
                    technique_id="T1526",
                    technique_name="Cloud Service Discovery"
                )
            ]
            # Add resource-specific techniques from the resource type lookup
            for tech_id in techniques:
                if tech_id in TECHNIQUE_DETAILS:
                    tactic, name = TECHNIQUE_DETAILS[tech_id]
                    threat_ttps.append(MitreTtp(tactic=tactic, technique_id=tech_id, technique_name=name))

            threats.append(Threat(
                threat_id="",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                severity=Severity.CRITICAL,
                resource_name=resource.name,
                resource_type=resource.resource_type,
                description=f"Resource '{resource.name}' is publicly accessible. Attackers can enumerate and target this resource during reconnaissance.",
                mitigation="Restrict access to private networks; use VPC endpoints and security groups.",
                trigger_property="exposure",
                mitre_ttps=threat_ttps,
            ))

        # Rule 10: Kubernetes Namespace with no NetworkPolicy
        if resource.resource_type == "Namespace" and resource.source_format == "kubernetes":
            if resource.properties.get("NetworkPolicy.missing") is True or resource.properties.get("has_network_policy") is not True:
                threats.append(Threat(
                    threat_id="",
                    stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                    severity=Severity.HIGH,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    description=f"Kubernetes namespace '{resource.name}' has no NetworkPolicy. Pods can communicate freely, enabling lateral movement.",
                    mitigation="Apply default-deny NetworkPolicy to the namespace; allow only required pod-to-pod traffic.",
                    trigger_property="NetworkPolicy.missing",
                    mitre_ttps=[MitreTtp(
                        tactic=MitreCategory.LATERAL_MOVEMENT,
                        technique_id="T1021",
                        technique_name="Remote Services"
                    )],
                ))

    return threats


# Module-level rule count for dynamic API responses
RULE_COUNT = 11
