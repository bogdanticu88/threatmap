# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✓         |

## Reporting a Vulnerability

Do **not** open a public GitHub issue for security vulnerabilities.

Send a report to **bogdanticuoffice@gmail.com** with:

- A description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Any suggested mitigations if you have them

You can expect an acknowledgement within 48 hours and a resolution timeline within 7 days of confirmation.

If the issue is confirmed, a patched release will be published and you will be credited in the release notes unless you request otherwise.

## Scope

This tool performs **static analysis only** — it makes no network calls and holds no credentials. The main attack surface is malicious IaC input files. Reports covering parser abuse (e.g. YAML bombs, malformed HCL causing excessive memory use) are in scope.
