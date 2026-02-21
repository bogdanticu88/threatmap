import json
import os

import yaml

# Loader that tolerates CloudFormation-specific YAML tags (!Ref, !Sub, etc.)
# without raising an error, so detect_format can read CFN templates.
class _TagTolerantLoader(yaml.SafeLoader):
    pass

_TagTolerantLoader.add_multi_constructor(
    "!",
    lambda loader, suffix, node: loader.construct_yaml_str(node)
    if isinstance(node, yaml.ScalarNode) else None,
)


def detect_format(filepath: str) -> str:
    """
    Return 'terraform', 'cloudformation', 'kubernetes', or 'unknown'.
    """
    _, ext = os.path.splitext(filepath.lower())

    if ext == ".tf":
        return "terraform"

    if ext == ".json":
        try:
            with open(filepath) as fh:
                data = json.load(fh)
            if "AWSTemplateFormatVersion" in data or (
                "Resources" in data
                and isinstance(data["Resources"], dict)
                and any(
                    isinstance(v, dict) and str(v.get("Type", "")).startswith("AWS::")
                    for v in data["Resources"].values()
                )
            ):
                return "cloudformation"
        except Exception:
            pass
        return "unknown"

    if ext in (".yaml", ".yml"):
        try:
            with open(filepath) as fh:
                docs = list(yaml.load_all(fh, Loader=_TagTolerantLoader))
        except Exception:
            return "unknown"

        # Check first non-None document
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if "AWSTemplateFormatVersion" in doc:
                return "cloudformation"
            # CloudFormation: top-level Resources with AWS:: types
            if "Resources" in doc and isinstance(doc["Resources"], dict):
                for v in doc["Resources"].values():
                    if isinstance(v, dict) and str(v.get("Type", "")).startswith("AWS::"):
                        return "cloudformation"
            # Kubernetes: apiVersion + kind at top level
            if "apiVersion" in doc and "kind" in doc:
                return "kubernetes"

    return "unknown"
