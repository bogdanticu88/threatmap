from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Resource:
    provider: str          # "aws", "azure", "gcp", "kubernetes"
    resource_type: str     # e.g. "aws_s3_bucket", "AWS::S3::Bucket", "Deployment"
    name: str              # logical name in the template
    properties: Dict[str, Any] = field(default_factory=dict)
    source_format: str = ""      # "terraform", "cloudformation", "kubernetes"
    source_file: str = ""
    relationships: List[str] = field(default_factory=list)
    exposure: str = "unknown"    # "public", "private", "unknown"

    @property
    def qualified_name(self) -> str:
        return f"{self.resource_type}.{self.name}"
