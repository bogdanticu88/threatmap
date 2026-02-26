"""
SARIF (Static Analysis Results Interchange Format) reporter.
Enables integration with GitHub Security Tab.
"""
import json
from datetime import datetime
from typing import List

from threatmap import __version__
from threatmap.models.resource import Resource
from threatmap.models.threat import Threat

def build_report(resources: List[Resource], threats: List[Threat], source_path: str) -> str:
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "threatmap",
                        "informationUri": "https://github.com/bogdanticu88/threatmap",
                        "semanticVersion": __version__,
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    rules = {}
    results = []

    severity_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note"
    }

    for t in threats:
        rule_id = f"TM-{t.stride_category.value.replace(' ', '-')}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f"STRIDE: {t.stride_category.value}"},
                "fullDescription": {"text": f"Threat detected in {t.stride_category.value} category."},
                "helpUri": "https://github.com/bogdanticu88/threatmap",
                "properties": {
                    "security-severity": "9.0" if t.severity.value == "CRITICAL" else "7.0"
                }
            }

        # Find the resource to get the file path
        res = next((r for r in resources if r.name == t.resource_name), None)
        file_path = res.source_file if res else source_path

        results.append({
            "ruleId": rule_id,
            "message": {"text": f"[{t.severity.value}] {t.description}\n\nMitigation: {t.mitigation}"},
            "level": severity_map.get(t.severity.value, "warning"),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": 1}
                    }
                }
            ]
        })

    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())
    sarif["runs"][0]["results"] = results

    return json.dumps(sarif, indent=2)
