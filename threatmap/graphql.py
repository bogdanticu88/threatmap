"""Strawberry GraphQL schema for threatmap analysis API."""
import os
import tempfile
from typing import Any, List, Optional

import strawberry
from strawberry.fastapi import GraphQLRouter

from threatmap import __version__
from threatmap.analyzers import engine, mitre as mitre_analyzer, pasta as pasta_analyzer
from threatmap.detect import detect_format
from threatmap.models.threat import MitreCategory, PastaElement
from threatmap.parsers import cloudformation, kubernetes, terraform


# JSON scalar for dynamic JSON responses
JSON = strawberry.scalar(
    Any,
    name="JSON",
    serialize=lambda v: v,
    parse_value=lambda v: v,
    description="Arbitrary JSON value",
)


@strawberry.type
class MitreTtpType:
    """MITRE ATT&CK tactic and technique."""

    tactic: str
    technique_id: str
    technique_name: str


@strawberry.type
class PastaThreatType:
    """PASTA framework threat context."""

    element: str
    actor_type: Optional[str] = None
    asset_type: Optional[str] = None
    scenario: Optional[str] = None


@strawberry.type
class ThreatType:
    """Infrastructure threat finding."""

    threat_id: str
    framework: str
    stride_category: str
    severity: str
    resource_name: str
    resource_type: str
    description: str
    mitigation: str
    trigger_property: Optional[str] = None
    remediation: Optional[str] = None
    mitre_ttps: Optional[List[MitreTtpType]] = None
    pasta_threat: Optional[PastaThreatType] = None


@strawberry.type
class AnalysisResultType:
    """Results from IaC threat analysis."""

    framework: str
    threat_count: int
    threats: List[ThreatType]


def _mitre_ttp_to_gql(ttp) -> MitreTtpType:
    """Convert internal MitreTtp to GraphQL type."""
    return MitreTtpType(
        tactic=ttp.tactic.value,
        technique_id=ttp.technique_id,
        technique_name=ttp.technique_name,
    )


def _pasta_threat_to_gql(pt) -> PastaThreatType:
    """Convert internal PastaThreat to GraphQL type."""
    return PastaThreatType(
        element=pt.element.value,
        actor_type=pt.actor_type,
        asset_type=pt.asset_type,
        scenario=pt.scenario,
    )


def _threat_to_gql(t, framework: str) -> ThreatType:
    """Convert internal Threat to GraphQL type."""
    return ThreatType(
        threat_id=t.threat_id,
        framework=framework,
        stride_category=t.stride_category.value,
        severity=t.severity.value,
        resource_name=t.resource_name,
        resource_type=t.resource_type,
        description=t.description,
        mitigation=t.mitigation,
        trigger_property=t.trigger_property,
        remediation=t.remediation,
        mitre_ttps=[_mitre_ttp_to_gql(ttp) for ttp in t.mitre_ttps] if t.mitre_ttps else None,
        pasta_threat=_pasta_threat_to_gql(t.pasta_threat) if t.pasta_threat else None,
    )


@strawberry.type
class Query:
    """GraphQL queries for threatmap."""

    @strawberry.field
    def health(self) -> str:
        """Health check endpoint."""
        return "ok"

    @strawberry.field
    def version(self) -> str:
        """API version."""
        return __version__

    @strawberry.field
    def rules(self) -> JSON:
        """Available threat modeling frameworks and rule counts."""
        return {
            "frameworks": ["stride", "mitre", "pasta"],
            "mitre_rules": mitre_analyzer.RULE_COUNT,
            "pasta_rules": pasta_analyzer.RULE_COUNT,
            "stride_note": "STRIDE rules are cloud-provider specific (aws, azure, gcp, kubernetes)",
        }


@strawberry.type
class Mutation:
    """GraphQL mutations for threatmap."""

    @strawberry.mutation
    def analyze(
        self,
        content: str,
        filename: str,
        framework: str = "stride",
    ) -> AnalysisResultType:
        """
        Analyze IaC content for threats.

        Args:
            content: IaC file content (Terraform, CloudFormation, Kubernetes YAML)
            filename: Original filename for format detection
            framework: Threat modeling framework (stride, mitre, pasta)

        Returns:
            AnalysisResultType with detected threats
        """
        if framework not in ["stride", "mitre", "pasta"]:
            raise ValueError(
                "Invalid framework. Use one of: stride, mitre, pasta"
            )

        # Write content to temporary file for detection and parsing
        suffix = "." + filename.rsplit(".", 1)[-1] if "." in filename else ".tf"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            temp_path = f.name

        try:
            # Detect format
            fmt = detect_format(temp_path)
            if fmt == "terraform":
                resources = terraform.parse_file(temp_path)
            elif fmt == "cloudformation":
                resources = cloudformation.parse_file(temp_path)
            elif fmt == "kubernetes":
                resources = kubernetes.parse_file(temp_path)
            else:
                raise ValueError(
                    f"Unsupported IaC format. Detected: {fmt}. "
                    "Supported: terraform, cloudformation, kubernetes"
                )

            # Run threat analysis engine
            threats = engine.run(resources, framework=framework)

            # Convert to GraphQL types
            gql_threats = [_threat_to_gql(t, framework) for t in threats]

            return AnalysisResultType(
                framework=framework,
                threat_count=len(threats),
                threats=gql_threats,
            )
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_path)
            except OSError:
                pass


# Initialize Strawberry GraphQL schema
schema = strawberry.Schema(query=Query, mutation=Mutation)

# Create FastAPI router for GraphQL
graphql_router = GraphQLRouter(schema)
