# threatmap

Static IaC threat modeler that parses Terraform, CloudFormation, and Kubernetes manifests and produces a structured STRIDE threat model report with a data flow diagram. No network calls, no cloud credentials, fully offline.

---

## Supported Formats and Providers

| Format | Provider | Extension |
|--------|----------|-----------|
| Terraform HCL | AWS, Azure, GCP | `.tf` |
| CloudFormation | AWS | `.yaml`, `.yml`, `.json` |
| Kubernetes manifests | Kubernetes | `.yaml`, `.yml` |

---

## Install

```bash
pip install -e .
```

Or from requirements:

```bash
pip install -r requirements.txt
pip install -e .
```

---

## Usage

Scan a directory and print a Markdown report to stdout:

```bash
threatmap scan ./terraform/
```

Scan multiple paths and write a JSON report to a file:

```bash
threatmap scan ./terraform/ ./k8s/ ./cloudformation/ --format json --output report.json
```

CI gate — exit code 1 if any CRITICAL or HIGH threat is found:

```bash
threatmap scan ./infra/ --fail-on HIGH --output threat-report.md
```

Print a terminal summary table only, without writing a full report:

```bash
threatmap scan ./infra/ --summary
```

---

## Output Example

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             Threat Summary                                  │
├────────┬──────────┬───────────────────────────┬──────────────┬─────────────┤
│ ID     │ Severity │ STRIDE                    │ Resource     │ Description │
├────────┼──────────┼───────────────────────────┼──────────────┼─────────────┤
│ T-001  │ CRITICAL │ Elevation of Privilege    │ admin-role   │ IAM role... │
│ T-002  │ CRITICAL │ Spoofing                  │ open-sg      │ Security... │
│ T-003  │ HIGH     │ Information Disclosure    │ main-db      │ RDS insta.. │
└────────┴──────────┴───────────────────────────┴──────────────┴─────────────┘
```

The full Markdown report includes:
- Executive summary with severity counts
- Resource inventory table
- Complete STRIDE threat table
- Per-threat mitigation guidance
- Mermaid data flow diagram

---

## CI Integration

```yaml
# .github/workflows/threat-model.yml
name: Threat Model

on: [pull_request]

jobs:
  threatmap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install threatmap
        run: pip install -r requirements.txt && pip install -e .

      - name: Run threat model scan
        run: |
          threatmap scan ./infra/ \
            --format markdown \
            --output threat-report.md \
            --fail-on HIGH

      - name: Upload threat report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: threat-report
          path: threat-report.md
```

---

## STRIDE Rule Coverage

| Provider | Rules |
|----------|-------|
| AWS (Terraform + CloudFormation) | 22 |
| Azure (Terraform) | 19 |
| GCP (Terraform) | 15 |
| Kubernetes | 17 |
| **Total** | **73** |

Categories covered per provider:

| Provider | S | T | R | I | D | E |
|----------|---|---|---|---|---|---|
| AWS | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Azure | ✓ | ✓ | ✓ | ✓ | — | ✓ |
| GCP | ✓ | ✓ | ✓ | ✓ | — | ✓ |
| Kubernetes | ✓ | ✓ | — | ✓ | ✓ | ✓ |

*(S=Spoofing, T=Tampering, R=Repudiation, I=Information Disclosure, D=Denial of Service, E=Elevation of Privilege)*

---

## Development

Run tests:

```bash
pytest tests/ -v
```

Run with coverage:

```bash
pytest tests/ --cov=threatmap --cov-report=term-missing
```

---

## Contributing

1. Fork the repository
2. Add rules in `threatmap/analyzers/<provider>.py` following the existing pattern
3. Add a fixture in `tests/fixtures/` that triggers the new rule
4. Add assertions in `tests/test_analyzers.py`
5. Open a pull request
