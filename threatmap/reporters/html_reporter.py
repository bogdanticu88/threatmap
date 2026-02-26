"""
Interactive HTML + Mermaid threat model report generator.
"""
from datetime import datetime
from typing import List

from jinja2 import Environment

from threatmap import __version__
from threatmap.models.resource import Resource
from threatmap.models.threat import Severity, Threat
from threatmap.reporters import markdown

_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Model Report - threatmap</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 2rem; background: #f9f9f9; }
        header { border-bottom: 2px solid #ddd; margin-bottom: 2rem; padding-bottom: 1rem; }
        h1 { color: #d32f2f; margin-bottom: 0; }
        .meta { color: #666; font-size: 0.9rem; margin-bottom: 2rem; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card { background: white; padding: 1rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; border-left: 5px solid #ddd; }
        .card.critical { border-left-color: #f44336; }
        .card.high { border-left-color: #ff9800; }
        .card.medium { border-left-color: #ffc107; }
        .card.low { border-left-color: #4caf50; }
        .card-num { font-size: 2rem; font-weight: bold; margin-bottom: 0.2rem; }
        .card-label { color: #666; font-size: 0.8rem; text-transform: uppercase; }
        .mermaid-container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 2rem; overflow-x: auto; }
        .threat-table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .threat-table th, .threat-table td { padding: 1rem; text-align: left; border-bottom: 1px solid #eee; }
        .threat-table th { background: #f5f5f5; font-weight: 600; }
        .severity { font-weight: bold; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }
        .sev-CRITICAL { background: #ffebee; color: #c62828; }
        .sev-HIGH { background: #fff3e0; color: #ef6c00; }
        .sev-MEDIUM { background: #fffde7; color: #f9a825; }
        .sev-LOW { background: #e8f5e9; color: #2e7d32; }
        .remediation { background: #f5f5f5; font-family: monospace; padding: 1rem; border-radius: 4px; border-left: 3px solid #ddd; white-space: pre-wrap; margin-top: 1rem; }
        footer { margin-top: 4rem; text-align: center; color: #999; font-size: 0.8rem; }
    </style>
</head>
<body>
    <header>
        <h1>Threat Model Report</h1>
        <div class="meta">Generated: {{ generated }} | Source: {{ source }} | threatmap v{{ version }}</div>
    </header>

    <div class="summary-cards">
        <div class="card critical"><div class="card-num">{{ counts.CRITICAL }}</div><div class="card-label">CRITICAL</div></div>
        <div class="card high"><div class="card-num">{{ counts.HIGH }}</div><div class="card-label">HIGH</div></div>
        <div class="card medium"><div class="card-num">{{ counts.MEDIUM }}</div><div class="card-label">MEDIUM</div></div>
        <div class="card low"><div class="card-num">{{ counts.LOW }}</div><div class="card-label">LOW</div></div>
    </div>

    <h2>Data Flow Diagram</h2>
    <div class="mermaid-container">
        <div class="mermaid">
{{ mermaid }}
        </div>
    </div>

    <h2>Threat Details</h2>
    <table class="threat-table">
        <thead>
            <tr>
                <th>ID</th>
                <th>Severity</th>
                <th>Category</th>
                <th>Resource</th>
                <th>Threat Description</th>
            </tr>
        </thead>
        <tbody>
            {% for t in threats %}
            <tr>
                <td>{{ t.threat_id }}</td>
                <td><span class="severity sev-{{ t.severity.value }}">{{ t.severity.value }}</span></td>
                <td>{{ t.stride_category.value }}</td>
                <td><strong>{{ t.resource_name }}</strong></td>
                <td>
                    <div>{{ t.description }}</div>
                    <div style="font-size: 0.85rem; color: #666; margin-top: 0.5rem;"><strong>Mitigation:</strong> {{ t.mitigation }}</div>
                    {% if t.remediation %}
                    <div class="remediation">{{ t.remediation }}</div>
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <footer>
        threatmap — static IaC threat modeler using STRIDE | <a href="https://github.com/bogdanticu88/threatmap" style="color: #999;">GitHub</a>
    </footer>

    <script>
        mermaid.initialize({ startOnLoad: true, theme: 'neutral', securityLevel: 'loose' });
    </script>
</body>
</html>
"""

def build_report(resources: List[Resource], threats: List[Threat], source_path: str) -> str:
    counts = {s.value: sum(1 for t in threats if t.severity == s) for s in Severity}
    mermaid = markdown._build_mermaid(resources, threats)

    env = Environment(autoescape=True)
    template = env.from_string(_HTML_TEMPLATE)

    return template.render(
        generated=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        source=source_path,
        version=__version__,
        counts=counts,
        threats=threats,
        mermaid=mermaid,
    )
