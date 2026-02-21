"""
Markdown + Mermaid threat model report generator.
"""
import re
from collections import defaultdict
from datetime import datetime
from typing import Dict, List

from jinja2 import Environment

from threatmap.models.resource import Resource
from threatmap.models.threat import Severity, Threat

_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "⚪",
}

_CATEGORY_MAP = {
    # Resource type prefix → subgraph label
    "aws_s3": "Data",
    "aws_db": "Data",
    "aws_rds": "Data",
    "google_sql": "Data",
    "google_storage": "Data",
    "azurerm_storage": "Data",
    "azurerm_mssql": "Data",
    "aws_kms": "Security",
    "azurerm_key_vault": "Security",
    "google_kms": "Security",
    "aws_security_group": "Networking",
    "aws_vpc": "Networking",
    "azurerm_network": "Networking",
    "google_compute_firewall": "Networking",
    "aws_cloudtrail": "Security",
    "aws_iam": "Identity",
    "azurerm_role": "Identity",
    "google_project_iam": "Identity",
    "aws_instance": "Compute",
    "aws_lambda": "Compute",
    "aws_eks": "Compute",
    "azurerm_linux_web_app": "Compute",
    "azurerm_windows_web_app": "Compute",
    "azurerm_kubernetes": "Compute",
    "azurerm_container": "Compute",
    "azurerm_linux_virtual": "Compute",
    "google_compute_instance": "Compute",
    "google_container": "Compute",
}

_K8S_SUBGRAPH = {
    "Deployment": "Kubernetes",
    "StatefulSet": "Kubernetes",
    "DaemonSet": "Kubernetes",
    "Pod": "Kubernetes",
    "Service": "Kubernetes",
    "Ingress": "Kubernetes",
    "ConfigMap": "Kubernetes",
    "Secret": "Kubernetes",
    "ServiceAccount": "Identity",
    "ClusterRole": "Identity",
    "Role": "Identity",
    "ClusterRoleBinding": "Identity",
    "RoleBinding": "Identity",
    "Namespace": "Kubernetes",
    "NetworkPolicy": "Networking",
}


def _sanitize_node_id(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", name)


def _resource_subgraph(r: Resource) -> str:
    if r.provider == "kubernetes":
        return _K8S_SUBGRAPH.get(r.resource_type, "Kubernetes")
    for prefix, label in _CATEGORY_MAP.items():
        if r.resource_type.startswith(prefix):
            return label
    return "Other"


def _node_shape(r: Resource) -> str:
    """Return a Mermaid node definition string (without ID)."""
    label = r.name
    rt = r.resource_type
    sg = _resource_subgraph(r)

    # Internet-exposed
    if r.exposure == "public":
        return f"(({label}))"
    # Databases and storage
    if sg == "Data":
        return f"[({label})]"
    # Network controls
    if sg == "Networking":
        return f"{{{label}}}"
    # Identity / RBAC
    if sg == "Identity":
        return f"[/{label}/]"
    # Default: box
    return f"[{label}]"


def _edge_label(src: Resource, dst_name: str, all_resources: Dict[str, Resource]) -> str:
    dst = all_resources.get(dst_name)
    if not dst:
        return "ref"
    src_sg = _resource_subgraph(src)
    dst_sg = _resource_subgraph(dst)
    if src_sg == "Compute" and dst_sg == "Data":
        if "sql" in dst.resource_type.lower() or "db" in dst.resource_type.lower():
            return "SQL"
        return "storage"
    if src_sg == "Kubernetes" and dst.resource_type == "Service":
        return "ClusterIP"
    if dst_sg == "Identity":
        return "assumes"
    return "ref"


def _count_by_severity(threats: List[Threat]) -> Dict[str, int]:
    counts: Dict[str, int] = {s.value: 0 for s in Severity}
    for t in threats:
        counts[t.severity.value] += 1
    return counts


def _build_mermaid(resources: List[Resource], threats: List[Threat]) -> str:
    # Map resource name → resource for edge label lookups
    resource_map: Dict[str, Resource] = {r.name: r for r in resources}

    # Map resource qualified_name → worst severity colour
    node_colors: Dict[str, str] = {}
    severity_color = {
        "CRITICAL": "fill:#ff4444,color:#fff",
        "HIGH": "fill:#ff8800,color:#fff",
        "MEDIUM": "fill:#ffcc00,color:#000",
        "LOW": "fill:#88cc00,color:#000",
    }
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    for t in threats:
        key = f"{t.resource_type}.{t.resource_name}"
        current = node_colors.get(key)
        if current is None or severity_rank[t.severity.value] < severity_rank.get(
            current, 99
        ):
            node_colors[key] = t.severity.value

    # Group by subgraph
    subgraphs: Dict[str, List[Resource]] = defaultdict(list)
    for r in resources:
        subgraphs[_resource_subgraph(r)].append(r)

    lines = ["flowchart LR"]

    # Check if there are any public-facing resources
    has_public = any(
        r.exposure == "public"
        or any(
            sg_kw in r.resource_type
            for sg_kw in ("ingress", "Ingress", "load_balancer", "LoadBalancer")
        )
        for r in resources
    )
    if has_public or any(r.resource_type in ("Ingress", "Service") for r in resources):
        lines.append('    Internet((Internet))')

    # Subgraph definitions
    sg_order = ["Networking", "Compute", "Kubernetes", "Data", "Security", "Identity", "Other"]
    for sg_name in sg_order:
        sg_resources = subgraphs.get(sg_name, [])
        if not sg_resources:
            continue
        lines.append(f"    subgraph {sg_name}")
        for r in sg_resources:
            node_id = _sanitize_node_id(r.qualified_name)
            shape = _node_shape(r)
            lines.append(f"        {node_id}{shape}")
        lines.append("    end")

    # Edges
    added_edges = set()
    for r in resources:
        src_id = _sanitize_node_id(r.qualified_name)
        for rel in r.relationships:
            # rel is like "aws_s3_bucket.my_bucket" or just a logical name
            parts = rel.rsplit(".", 1)
            dst_name = parts[-1]
            dst_resource = resource_map.get(dst_name)
            if dst_resource:
                dst_id = _sanitize_node_id(dst_resource.qualified_name)
            else:
                dst_id = _sanitize_node_id(dst_name)
            edge_key = (src_id, dst_id)
            if edge_key not in added_edges and src_id != dst_id:
                added_edges.add(edge_key)
                label = _edge_label(r, dst_name, resource_map)
                lines.append(f"    {src_id} -->|{label}| {dst_id}")

    # Internet → Ingress/exposed service edges
    if has_public or any(r.resource_type in ("Ingress", "Service") for r in resources):
        for r in resources:
            if r.resource_type in ("Ingress",) or r.exposure == "public":
                dst_id = _sanitize_node_id(r.qualified_name)
                edge_key = ("Internet", dst_id)
                if edge_key not in added_edges:
                    added_edges.add(edge_key)
                    lines.append(f"    Internet -->|HTTPS| {dst_id}")

    # Styling
    for r in resources:
        qn = r.qualified_name
        if qn in node_colors:
            node_id = _sanitize_node_id(qn)
            color = severity_color.get(node_colors[qn], "")
            if color:
                lines.append(f"    style {node_id} {color}")

    return "\n".join(lines)


_TEMPLATE = """\
# Threat Model Report

**Generated:** {{ generated }}
**Source:** {{ source }}
**Tool:** threatmap v1.0.0

---

## Executive Summary

Analysis of **{{ resource_count }} resources** across {{ formats }} identified **{{ threat_count }} threats**:
{% for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] %}
- **{{ sev }}**: {{ counts[sev] }}{% endfor %}

{% if counts["CRITICAL"] > 0 or counts["HIGH"] > 0 %}
Immediate attention is required for CRITICAL and HIGH findings before this infrastructure is used in production.
{% else %}
No CRITICAL or HIGH severity issues were detected. Review MEDIUM findings as capacity allows.
{% endif %}

---

## Resource Inventory

| # | Resource | Type | Provider | Format | Exposure |
|---|----------|------|----------|--------|----------|
{% for r in resources %}| {{ loop.index }} | `{{ r.name }}` | `{{ r.resource_type }}` | {{ r.provider }} | {{ r.source_format }} | {{ r.exposure }} |
{% endfor %}

---

## STRIDE Threat Analysis

| ID | Severity | STRIDE Category | Resource | Description |
|----|----------|----------------|----------|-------------|
{% for t in threats %}| {{ t.threat_id }} | {{ sev_icon[t.severity.value] }} {{ t.severity.value }} | {{ t.stride_category.value }} | `{{ t.resource_name }}` | {{ t.description }} |
{% endfor %}

---

## Mitigations

{% for t in threats %}
### {{ t.threat_id }} — {{ t.stride_category.value }} ({{ t.severity.value }})

**Resource:** `{{ t.resource_type }}.{{ t.resource_name }}`
{% if t.trigger_property %}**Property:** `{{ t.trigger_property }}`
{% endif %}**Finding:** {{ t.description }}

**Mitigation:** {{ t.mitigation }}

---
{% endfor %}

## Data Flow Diagram

```mermaid
{{ mermaid }}
```
"""


def build_report(resources: List[Resource], threats: List[Threat], source_path: str) -> str:
    counts = _count_by_severity(threats)
    formats_seen = sorted({r.source_format for r in resources if r.source_format})
    formats_str = ", ".join(formats_seen) if formats_seen else "unknown"

    mermaid = _build_mermaid(resources, threats)

    env = Environment(autoescape=False)
    template = env.from_string(_TEMPLATE)

    return template.render(
        generated=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        source=source_path,
        resource_count=len(resources),
        formats=formats_str,
        threat_count=len(threats),
        counts=counts,
        resources=resources,
        threats=threats,
        sev_icon=_SEVERITY_EMOJI,
        mermaid=mermaid,
    )
