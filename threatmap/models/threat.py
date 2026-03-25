from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional, List, Dict, Any


class StrideCategory(str, Enum):
    SPOOFING               = "Spoofing"
    TAMPERING              = "Tampering"
    REPUDIATION            = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE      = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class MitreCategory(str, Enum):
    """MITRE ATT&CK Framework Tactics"""
    RECONNAISSANCE         = "Reconnaissance"
    RESOURCE_DEVELOPMENT  = "Resource Development"
    INITIAL_ACCESS        = "Initial Access"
    EXECUTION              = "Execution"
    PERSISTENCE            = "Persistence"
    PRIVILEGE_ESCALATION  = "Privilege Escalation"
    DEFENSE_EVASION       = "Defense Evasion"
    CREDENTIAL_ACCESS     = "Credential Access"
    DISCOVERY              = "Discovery"
    LATERAL_MOVEMENT      = "Lateral Movement"
    COLLECTION             = "Collection"
    COMMAND_AND_CONTROL   = "Command and Control"
    EXFILTRATION           = "Exfiltration"
    IMPACT                 = "Impact"


class PastaElement(str, Enum):
    """PASTA Framework Elements"""
    ASSET                  = "Asset"
    ACTOR                  = "Actor"
    SCENARIO               = "Scenario"
    VULNERABILITY          = "Vulnerability"
    COUNTERMEASURE         = "Countermeasure"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class MitreTtp:
    """MITRE ATT&CK Technique"""
    tactic: MitreCategory
    technique_id: str
    technique_name: str


@dataclass
class PastaThreat:
    """PASTA Framework Threat"""
    element: PastaElement
    actor_type: Optional[str] = None
    asset_type: Optional[str] = None
    scenario: Optional[str] = None


@dataclass
class Threat:
    threat_id: str
    stride_category: StrideCategory
    severity: Severity
    resource_name: str
    resource_type: str
    description: str
    mitigation: str
    trigger_property: Optional[str] = None
    remediation: Optional[str] = None
    mitre_ttps: Optional[List[MitreTtp]] = None
    pasta_threat: Optional[PastaThreat] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "threat_id": self.threat_id,
            "stride_category": self.stride_category.value,
            "severity": self.severity.value,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "description": self.description,
            "mitigation": self.mitigation,
            "trigger_property": self.trigger_property,
            "remediation": self.remediation,
        }

        if self.mitre_ttps:
            d["mitre_ttps"] = [
                {
                    "tactic": ttp.tactic.value,
                    "technique_id": ttp.technique_id,
                    "technique_name": ttp.technique_name,
                }
                for ttp in self.mitre_ttps
            ]

        if self.pasta_threat:
            d["pasta_threat"] = {
                "element": self.pasta_threat.element.value,
                "actor_type": self.pasta_threat.actor_type,
                "asset_type": self.pasta_threat.asset_type,
                "scenario": self.pasta_threat.scenario,
            }

        return d
