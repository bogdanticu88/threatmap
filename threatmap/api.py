"""FastAPI service for threatmap threat analysis."""
import tempfile
from typing import List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel

from threatmap import __version__
from threatmap.analyzers import engine
from threatmap.detect import detect_format
from threatmap.parsers import cloudformation, kubernetes, terraform
from threatmap.reporters import json_reporter

app = FastAPI(
    title="Threatmap",
    description="Static IaC threat modeler using STRIDE, MITRE, and PASTA frameworks",
    version=__version__
)


class AnalysisRequest(BaseModel):
    """Request body for threat analysis."""
    content: str
    filename: str
    framework: str = "stride"


class ThreatResponse(BaseModel):
    """Threat analysis result."""
    threat_id: str
    framework: str
    severity: str
    resource_name: str
    resource_type: str
    description: str
    mitigation: str
    trigger_property: Optional[str] = None
    remediation: Optional[str] = None


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
        "stride_rules": 73,
        "note": "MITRE and PASTA rules coming in v2.0.1"
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
                severity=t.severity.value,
                resource_name=t.resource_name,
                resource_type=t.resource_type,
                description=t.description,
                mitigation=t.mitigation,
                trigger_property=t.trigger_property,
                remediation=t.remediation
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
