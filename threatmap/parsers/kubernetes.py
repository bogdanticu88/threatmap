import os
from typing import Any, Dict, List, Optional

import yaml
from rich.console import Console

from threatmap.detect import detect_format
from threatmap.models.resource import Resource

console = Console(stderr=True)

# Kinds we understand and want to analyze
SUPPORTED_KINDS = {
    "Deployment", "StatefulSet", "DaemonSet", "Pod",
    "Service", "Ingress",
    "ConfigMap", "Secret",
    "ServiceAccount",
    "ClusterRole", "Role",
    "ClusterRoleBinding", "RoleBinding",
    "Namespace",
    "NetworkPolicy",
    "PersistentVolumeClaim", "PersistentVolume",
    "Job", "CronJob",
}


def _scan_refs(val: Any, keys: List[str]) -> List[str]:
    """
    Recursively scan spec dict for values at the given keys.
    Returns a list of string references found.
    """
    refs = []
    if isinstance(val, dict):
        for k, v in val.items():
            if k in keys and isinstance(v, str):
                refs.append(v)
            refs.extend(_scan_refs(v, keys))
    elif isinstance(val, list):
        for item in val:
            refs.extend(_scan_refs(item, keys))
    return refs


_REF_KEYS = {
    "serviceAccountName", "clusterRoleName", "secretRef",
    "configMapRef", "claimRef", "roleName",
}


def parse_file(filepath: str) -> List[Resource]:
    resources: List[Resource] = []

    try:
        with open(filepath) as fh:
            docs = list(yaml.safe_load_all(fh))
    except Exception as exc:
        console.print(f"[yellow]Warning:[/yellow] failed to parse {filepath}: {exc}")
        return resources

    for doc in docs:
        if not isinstance(doc, dict):
            continue

        kind = doc.get("kind", "")
        if kind not in SUPPORTED_KINDS:
            console.print(
                f"[dim]Debug:[/dim] skipping unsupported kind '{kind}' in {filepath}"
            )
            continue

        metadata = doc.get("metadata", {}) or {}
        name = metadata.get("name", "unnamed")
        spec = doc.get("spec", {}) or {}

        refs = _scan_refs(spec, _REF_KEYS)

        r = Resource(
            provider="kubernetes",
            resource_type=kind,
            name=name,
            properties=doc,        # store the full document for analyzers
            source_format="kubernetes",
            source_file=filepath,
            relationships=list(set(refs)),
        )
        resources.append(r)

    return resources


def parse_directory(path: str) -> List[Resource]:
    resources: List[Resource] = []

    if os.path.isfile(path):
        if detect_format(path) == "kubernetes":
            resources.extend(parse_file(path))
        return resources

    for root, _, files in os.walk(path):
        for fname in files:
            fpath = os.path.join(root, fname)
            if detect_format(fpath) == "kubernetes":
                resources.extend(parse_file(fpath))

    return resources
