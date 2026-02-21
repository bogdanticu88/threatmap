from dataclasses import dataclass
from enum import Enum
from typing import Optional


class StrideCategory(str, Enum):
    SPOOFING               = "Spoofing"
    TAMPERING              = "Tampering"
    REPUDIATION            = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE      = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


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

    def to_dict(self) -> dict:
        return {
            "threat_id": self.threat_id,
            "stride_category": self.stride_category.value,
            "severity": self.severity.value,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "description": self.description,
            "mitigation": self.mitigation,
            "trigger_property": self.trigger_property,
        }
