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
        "T1537": "Exfiltrate Data to Cloud Storage",
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
        # Analyze IAM resources
        if "iam" in resource.resource_type.lower():
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

        # Analyze public exposure
        if resource.exposure == "public":
            techniques = _get_techniques_for_resource(resource.resource_type)
            threat_ttps = []
            for tactic in [MitreCategory.INITIAL_ACCESS, MitreCategory.RECONNAISSANCE]:
                threat_ttps.append(MitreTtp(
                    tactic=tactic,
                    technique_id="T1526" if tactic == MitreCategory.RECONNAISSANCE else "T1199",
                    technique_name="Cloud Service Discovery" if tactic == MitreCategory.RECONNAISSANCE else "Trusted Relationship",
                ))

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

        # Analyze encryption status
        if "encrypted" in resource.properties and resource.properties.get("encrypted") is False:
            threats.append(Threat(
                threat_id="",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                severity=Severity.HIGH,
                resource_name=resource.name,
                resource_type=resource.resource_type,
                description="Resource lacks encryption at rest. Data could be exposed if storage is accessed or compromised.",
                mitigation="Enable encryption at rest using provider-managed or customer-managed keys.",
                trigger_property="encrypted",
                mitre_ttps=_get_mitre_ttps_for_stride(StrideCategory.INFORMATION_DISCLOSURE.value),
            ))

    return threats
