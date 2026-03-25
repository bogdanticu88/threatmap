"""FastAPI service for threatmap threat analysis."""
import os
import tempfile
from typing import List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel

from threatmap import __version__
from threatmap.analyzers import engine, mitre as mitre_analyzer, pasta as pasta_analyzer
from threatmap.detect import detect_format
from threatmap.graphql import graphql_router
from threatmap.parsers import cloudformation, kubernetes, terraform
from threatmap.reporters import json_reporter

app = FastAPI(
    title="Threatmap",
    description="Static IaC threat modeler using STRIDE, MITRE, and PASTA frameworks",
    version=__version__
)

# Mount GraphQL router
app.include_router(graphql_router, prefix="/graphql")


class AnalysisRequest(BaseModel):
    """Request body for threat analysis."""

    content: str
    filename: str
    framework: str = "stride"


class MitreTtpResponse(BaseModel):
    """MITRE ATT&CK tactic and technique."""

    tactic: str
    technique_id: str
    technique_name: str


class PastaThreatResponse(BaseModel):
    """PASTA framework threat context."""

    element: str
    actor_type: Optional[str] = None
    asset_type: Optional[str] = None
    scenario: Optional[str] = None


class ThreatResponse(BaseModel):
    """Threat analysis result."""

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
    mitre_ttps: Optional[List[MitreTtpResponse]] = None
    pasta_threat: Optional[PastaThreatResponse] = None


class AnalysisResponse(BaseModel):
    """Analysis response containing threats and metadata."""

    framework: str
    threat_count: int
    threats: List[ThreatResponse]


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/version")
async def get_version():
    """Get threatmap version."""
    return {"version": __version__}


@app.get("/rules")
async def get_rules():
    """Get available frameworks and rule count."""
    return {
        "frameworks": ["stride", "mitre", "pasta"],
        "mitre_rules": mitre_analyzer.RULE_COUNT,
        "pasta_rules": pasta_analyzer.RULE_COUNT,
        "stride_note": "STRIDE rules are cloud-provider specific (aws, azure, gcp, kubernetes)",
    }


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: AnalysisRequest):
    """
    Analyze infrastructure code for threats.

    Supports:
    - Terraform HCL
    - CloudFormation YAML/JSON
    - Kubernetes manifests

    Frameworks: stride, mitre, pasta
    """
    if request.framework not in ["stride", "mitre", "pasta"]:
        raise HTTPException(status_code=400, detail="Invalid framework. Use: stride, mitre, or pasta")

    try:
        # Write content to temp file for parsing
        with tempfile.NamedTemporaryFile(mode='w', suffix=f".{request.filename.split('.')[-1]}", delete=False) as f:
            f.write(request.content)
            temp_path = f.name

        # Detect format and parse
        fmt = detect_format(temp_path)
        if fmt == "terraform":
            resources = terraform.parse_file(temp_path)
        elif fmt == "cloudformation":
            resources = cloudformation.parse_file(temp_path)
        elif fmt == "kubernetes":
            resources = kubernetes.parse_file(temp_path)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported file format: {fmt}")

        # Run analysis
        threats = engine.run(resources, framework=request.framework)

        # Convert to response format
        threat_list = [
            ThreatResponse(
                threat_id=t.threat_id,
                framework=request.framework,
                stride_category=t.stride_category.value,
                severity=t.severity.value,
                resource_name=t.resource_name,
                resource_type=t.resource_type,
                description=t.description,
                mitigation=t.mitigation,
                trigger_property=t.trigger_property,
                remediation=t.remediation,
                mitre_ttps=[
                    MitreTtpResponse(
                        tactic=ttp.tactic.value,
                        technique_id=ttp.technique_id,
                        technique_name=ttp.technique_name,
                    )
                    for ttp in t.mitre_ttps
                ]
                if t.mitre_ttps
                else None,
                pasta_threat=PastaThreatResponse(
                    element=t.pasta_threat.element.value,
                    actor_type=t.pasta_threat.actor_type,
                    asset_type=t.pasta_threat.asset_type,
                    scenario=t.pasta_threat.scenario,
                )
                if t.pasta_threat
                else None,
            )
            for t in threats
        ]

        return AnalysisResponse(
            framework=request.framework,
            threat_count=len(threats),
            threats=threat_list
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/analyze/file")
async def analyze_file(file: UploadFile = File(...), framework: str = "stride"):
    """
    Analyze uploaded infrastructure file.

    Supports multipart file upload.
    """
    if framework not in ["stride", "mitre", "pasta"]:
        raise HTTPException(status_code=400, detail="Invalid framework. Use: stride, mitre, or pasta")

    try:
        content = await file.read()
        text_content = content.decode('utf-8')

        request = AnalysisRequest(
            content=text_content,
            filename=file.filename or "uploaded",
            framework=framework
        )

        return await analyze(request)

    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8 text")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")
