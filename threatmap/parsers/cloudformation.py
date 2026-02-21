import json
import os
from typing import Any, Dict, List

import yaml
from rich.console import Console

from threatmap.detect import detect_format
from threatmap.models.resource import Resource

console = Console(stderr=True)


# ------------------------------------------------------------------ CFN YAML loader
# yaml.safe_load can't handle CloudFormation-specific tags (!Ref, !Sub, !If, etc.).
# We register multi-constructors that turn them into plain dicts so the rest of the
# parser can operate on normal Python objects.

class _CfnLoader(yaml.SafeLoader):
    pass


def _cfn_tag_constructor(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> Any:
    """Convert any !Tag into {"Tag": value} so downstream code can traverse it."""
    if isinstance(node, yaml.ScalarNode):
        return {tag_suffix: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {tag_suffix: loader.construct_sequence(node, deep=True)}
    if isinstance(node, yaml.MappingNode):
        return {tag_suffix: loader.construct_mapping(node, deep=True)}
    return {tag_suffix: None}


# Catch all tags that start with "!" — CloudFormation uses many of them
_CfnLoader.add_multi_constructor("!", _cfn_tag_constructor)


def _extract_refs(val: Any, refs: List[str]) -> None:
    """
    Recursively scan a post-load value for CloudFormation cross-references.
    After loading with _CfnLoader:
      !Ref LogicalName  → {"Ref": "LogicalName"}
      !GetAtt A.B       → {"GetAtt": "A.B"}  or {"Fn::GetAtt": [...]}
    """
    if isinstance(val, dict):
        # !Ref → {"Ref": "Name"}
        if "Ref" in val and isinstance(val["Ref"], str):
            refs.append(val["Ref"])
        # !GetAtt A.B → {"GetAtt": "A.B"}
        if "GetAtt" in val and isinstance(val["GetAtt"], str):
            refs.append(val["GetAtt"].split(".")[0])
        # Fn::GetAtt: [Name, Attr]
        if "Fn::GetAtt" in val:
            att = val["Fn::GetAtt"]
            if isinstance(att, list) and att:
                refs.append(att[0])
        for v in val.values():
            _extract_refs(v, refs)
    elif isinstance(val, list):
        for item in val:
            _extract_refs(item, refs)


def _cfn_to_provider(resource_type: str) -> str:
    # CloudFormation is AWS-only
    return "aws"


def parse_file(filepath: str) -> List[Resource]:
    resources: List[Resource] = []

    try:
        _, ext = os.path.splitext(filepath.lower())
        if ext == ".json":
            with open(filepath) as fh:
                template = json.load(fh)
        else:
            with open(filepath) as fh:
                template = yaml.load(fh, Loader=_CfnLoader)
    except Exception as exc:
        console.print(f"[yellow]Warning:[/yellow] failed to parse {filepath}: {exc}")
        return resources

    if not isinstance(template, dict):
        return resources

    cfn_resources = template.get("Resources", {})
    if not isinstance(cfn_resources, dict):
        return resources

    for logical_name, definition in cfn_resources.items():
        if not isinstance(definition, dict):
            continue
        resource_type = definition.get("Type", "")
        properties = definition.get("Properties", {}) or {}

        refs: List[str] = []
        _extract_refs(properties, refs)

        r = Resource(
            provider=_cfn_to_provider(resource_type),
            resource_type=resource_type,
            name=logical_name,
            properties=properties,
            source_format="cloudformation",
            source_file=filepath,
            relationships=list(set(refs)),
        )
        resources.append(r)

    return resources


def parse_directory(path: str) -> List[Resource]:
    resources: List[Resource] = []

    if os.path.isfile(path):
        if detect_format(path) == "cloudformation":
            resources.extend(parse_file(path))
        return resources

    for root, _, files in os.walk(path):
        for fname in files:
            fpath = os.path.join(root, fname)
            if detect_format(fpath) == "cloudformation":
                resources.extend(parse_file(fpath))

    return resources
