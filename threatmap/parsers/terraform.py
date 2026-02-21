import os
import re
from typing import Any, Dict, List

import hcl2
from rich.console import Console

from threatmap.detect import detect_format
from threatmap.models.resource import Resource

console = Console(stderr=True)

# Regex to find cross-resource references in property string values
_REF_RE = re.compile(r'(aws_|azurerm_|google_)\w+\.\w+')


def _infer_provider(resource_type: str) -> str:
    if resource_type.startswith("aws_"):
        return "aws"
    if resource_type.startswith("azurerm_"):
        return "azure"
    if resource_type.startswith("google_"):
        return "gcp"
    return "unknown"


def _unwrap(val: Any) -> Any:
    """
    python-hcl2 wraps single-element blocks in a list.
    Recursively unwrap single-element lists that contain dicts.
    """
    if isinstance(val, list):
        if len(val) == 1 and isinstance(val[0], dict):
            return _unwrap(val[0])
        return [_unwrap(v) for v in val]
    if isinstance(val, dict):
        return {k: _unwrap(v) for k, v in val.items()}
    return val


def _extract_refs(val: Any) -> List[str]:
    """Recursively scan property values for cross-resource references."""
    refs = []
    if isinstance(val, str):
        refs.extend(_REF_RE.findall(val))
        # Return the full match, not just the prefix
        refs = _REF_RE.findall(val)
    elif isinstance(val, list):
        for item in val:
            refs.extend(_extract_refs(item))
    elif isinstance(val, dict):
        for v in val.values():
            refs.extend(_extract_refs(v))
    return refs


def _extract_all_refs(props: Dict[str, Any]) -> List[str]:
    refs = []
    for v in props.values():
        refs.extend(_extract_refs(v))
    return list(set(refs))


def parse_file(filepath: str) -> List[Resource]:
    resources: List[Resource] = []
    try:
        with open(filepath) as fh:
            data = hcl2.load(fh)
    except Exception as exc:
        console.print(f"[yellow]Warning:[/yellow] failed to parse {filepath}: {exc}")
        return resources

    for resource_block in data.get("resource", []):
        for resource_type, instances in resource_block.items():
            if isinstance(instances, list):
                # hcl2 wraps the block in a list
                for instance_map in instances:
                    if not isinstance(instance_map, dict):
                        continue
                    for name, raw_props in instance_map.items():
                        props = _unwrap(raw_props) if isinstance(raw_props, dict) else {}
                        if not isinstance(props, dict):
                            props = {}
                        provider = _infer_provider(resource_type)
                        refs = _extract_all_refs(props)
                        r = Resource(
                            provider=provider,
                            resource_type=resource_type,
                            name=name,
                            properties=props,
                            source_format="terraform",
                            source_file=filepath,
                            relationships=refs,
                        )
                        resources.append(r)
            elif isinstance(instances, dict):
                for name, raw_props in instances.items():
                    props = _unwrap(raw_props) if isinstance(raw_props, dict) else {}
                    if not isinstance(props, dict):
                        props = {}
                    provider = _infer_provider(resource_type)
                    refs = _extract_all_refs(props)
                    r = Resource(
                        provider=provider,
                        resource_type=resource_type,
                        name=name,
                        properties=props,
                        source_format="terraform",
                        source_file=filepath,
                        relationships=refs,
                    )
                    resources.append(r)

    return resources


def parse_directory(path: str) -> List[Resource]:
    resources: List[Resource] = []

    if os.path.isfile(path):
        if detect_format(path) == "terraform":
            resources.extend(parse_file(path))
        return resources

    for root, _, files in os.walk(path):
        for fname in files:
            fpath = os.path.join(root, fname)
            if detect_format(fpath) == "terraform":
                resources.extend(parse_file(fpath))

    return resources
