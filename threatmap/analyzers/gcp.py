"""
GCP STRIDE rules — covers Terraform google_* resources.
"""
from typing import Any, Dict, List, Optional

from threatmap.models.resource import Resource
from threatmap.models.threat import Severity, StrideCategory, Threat

_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
_PRIVILEGED_ROLES = {"roles/owner", "roles/editor"}


def _make(
    rule_id: str,
    stride: StrideCategory,
    severity: Severity,
    resource: Resource,
    description: str,
    mitigation: str,
    trigger: Optional[str] = None,
) -> Threat:
    return Threat(
        threat_id="",
        stride_category=stride,
        severity=severity,
        resource_name=resource.name,
        resource_type=resource.resource_type,
        description=description,
        mitigation=mitigation,
        trigger_property=trigger,
    )


def _get(props: Dict, *keys, default=None) -> Any:
    cur = props
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
        if cur is None:
            return default
    return cur


def _port_in_list(ports: Any, target: int) -> bool:
    if ports is None:
        return True   # all ports
    if isinstance(ports, list):
        for p in ports:
            s = str(p)
            if "-" in s:
                parts = s.split("-", 1)
                try:
                    if int(parts[0]) <= target <= int(parts[1]):
                        return True
                except ValueError:
                    pass
            else:
                try:
                    if int(s) == target:
                        return True
                except ValueError:
                    pass
    return False


def analyze(resources: List[Resource]) -> List[Threat]:
    threats: List[Threat] = []

    gcp_resources = [r for r in resources if r.provider == "gcp"]

    for r in gcp_resources:
        p = r.properties
        rt = r.resource_type

        # ----------------------------------------- GCS Bucket
        if rt == "google_storage_bucket":
            # GCP-001: uniform bucket-level access
            iam_config = p.get("uniform_bucket_level_access")
            if iam_config is None:
                # Also check inside iam_configuration block
                iam_block = p.get("iam_configuration", {}) or {}
                iam_config = iam_block.get("uniform_bucket_level_access", {}).get("enabled")
            if str(iam_config).lower() not in ("true",):
                threats.append(_make(
                    "GCP-001", StrideCategory.ELEVATION_OF_PRIVILEGE,
                    Severity.HIGH, r,
                    f"GCS bucket '{r.name}' does not have uniform bucket-level access enabled — legacy ACLs can bypass IAM policies.",
                    "Set uniform_bucket_level_access = true.",
                    "uniform_bucket_level_access",
                ))

            # GCP-002: public access prevention
            pub_prev = p.get("public_access_prevention")
            if str(pub_prev).lower() != "enforced":
                threats.append(_make(
                    "GCP-002", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.HIGH, r,
                    f"GCS bucket '{r.name}' does not enforce public access prevention — allUsers or allAuthenticatedUsers ACLs are possible.",
                    "Set public_access_prevention = \"enforced\".",
                    "public_access_prevention",
                ))

            # GCP-003: logging
            logging_block = p.get("logging")
            if not logging_block:
                threats.append(_make(
                    "GCP-003", StrideCategory.REPUDIATION,
                    Severity.MEDIUM, r,
                    f"GCS bucket '{r.name}' does not have access logging configured.",
                    "Add a logging block pointing to a dedicated audit bucket.",
                    "logging",
                ))

        # ----------------------------------------- Compute Firewall
        if rt == "google_compute_firewall":
            allow_rules = p.get("allow", [])
            if isinstance(allow_rules, dict):
                allow_rules = [allow_rules]
            source_ranges = p.get("source_ranges", [])

            if any(c in _OPEN_CIDRS for c in source_ranges):
                # GCP-004: any open allow rule
                threats.append(_make(
                    "GCP-004", StrideCategory.SPOOFING,
                    Severity.HIGH, r,
                    f"Firewall rule '{r.name}' allows ingress from 0.0.0.0/0.",
                    "Restrict source_ranges to known CIDR ranges.",
                    "source_ranges",
                ))

                # GCP-005: SSH/RDP
                for allow in allow_rules:
                    if not isinstance(allow, dict):
                        continue
                    ports = allow.get("ports")
                    if _port_in_list(ports, 22) or _port_in_list(ports, 3389):
                        threats.append(_make(
                            "GCP-005", StrideCategory.SPOOFING,
                            Severity.CRITICAL, r,
                            f"Firewall rule '{r.name}' exposes SSH/RDP to 0.0.0.0/0.",
                            "Remove public SSH/RDP access. Use OS Login and Identity-Aware Proxy.",
                            "allow.ports.ssh_rdp",
                        ))
                        break

        # ----------------------------------------- Compute Instance
        if rt == "google_compute_instance":
            metadata = p.get("metadata", {}) or {}

            # GCP-006: block-project-ssh-keys
            block_ssh = metadata.get("block-project-ssh-keys")
            if str(block_ssh).lower() != "true":
                threats.append(_make(
                    "GCP-006", StrideCategory.SPOOFING,
                    Severity.MEDIUM, r,
                    f"Compute instance '{r.name}' does not block project-wide SSH keys — any project key can access the instance.",
                    "Set metadata.block-project-ssh-keys = \"true\".",
                    "metadata.block-project-ssh-keys",
                ))

            # GCP-007: shielded VM
            shielded = p.get("shielded_instance_config")
            if not shielded:
                threats.append(_make(
                    "GCP-007", StrideCategory.TAMPERING,
                    Severity.MEDIUM, r,
                    f"Compute instance '{r.name}' does not have Shielded VM configuration — boot integrity cannot be verified.",
                    "Add a shielded_instance_config block with enable_secure_boot = true and enable_vtpm = true.",
                    "shielded_instance_config",
                ))

        # ----------------------------------------- Cloud SQL
        if rt == "google_sql_database_instance":
            settings = p.get("settings", {}) or {}
            ip_config = settings.get("ip_configuration", {}) or {}
            backup_config = settings.get("backup_configuration", {}) or {}

            # GCP-008: public IP
            ipv4 = ip_config.get("ipv4_enabled")
            if str(ipv4).lower() not in ("false",):
                threats.append(_make(
                    "GCP-008", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.HIGH, r,
                    f"Cloud SQL instance '{r.name}' has a public IPv4 address assigned.",
                    "Set ip_configuration.ipv4_enabled = false and use Cloud SQL Auth Proxy or private IP.",
                    "settings.ip_configuration.ipv4_enabled",
                ))

            # GCP-009: backups
            backup_enabled = backup_config.get("enabled")
            if str(backup_enabled).lower() not in ("true",):
                threats.append(_make(
                    "GCP-009", StrideCategory.TAMPERING,
                    Severity.MEDIUM, r,
                    f"Cloud SQL instance '{r.name}' does not have automated backups enabled.",
                    "Set settings.backup_configuration.enabled = true.",
                    "settings.backup_configuration.enabled",
                ))

        # ----------------------------------------- GKE Cluster
        if rt == "google_container_cluster":
            # GCP-010: master authorized networks
            master_auth_nets = p.get("master_authorized_networks_config")
            if not master_auth_nets:
                threats.append(_make(
                    "GCP-010", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.HIGH, r,
                    f"GKE cluster '{r.name}' has no master_authorized_networks_config — API server is publicly reachable from any IP.",
                    "Add a master_authorized_networks_config block restricting access to known CIDRs.",
                    "master_authorized_networks_config",
                ))

            # GCP-011: network policy
            net_policy = p.get("network_policy", {}) or {}
            if isinstance(net_policy, dict):
                if str(net_policy.get("enabled")).lower() != "true":
                    threats.append(_make(
                        "GCP-011", StrideCategory.TAMPERING,
                        Severity.HIGH, r,
                        f"GKE cluster '{r.name}' does not have network policy enforcement enabled — pods can communicate without restriction.",
                        "Enable network_policy with provider = \"CALICO\" or another supported CNI.",
                        "network_policy.enabled",
                    ))
            else:
                threats.append(_make(
                    "GCP-011", StrideCategory.TAMPERING,
                    Severity.HIGH, r,
                    f"GKE cluster '{r.name}' does not have network_policy configured.",
                    "Configure network_policy.enabled = true.",
                    "network_policy",
                ))

            # GCP-012: workload identity
            workload_id = p.get("workload_identity_config")
            if not workload_id:
                threats.append(_make(
                    "GCP-012", StrideCategory.ELEVATION_OF_PRIVILEGE,
                    Severity.HIGH, r,
                    f"GKE cluster '{r.name}' does not have Workload Identity configured — pods may use node-level service account credentials.",
                    "Configure workload_identity_config with the workload_pool.",
                    "workload_identity_config",
                ))

        # ----------------------------------------- Project IAM
        if rt in ("google_project_iam_binding", "google_project_iam_member"):
            role = p.get("role", "")
            if role in _PRIVILEGED_ROLES:
                threats.append(_make(
                    "GCP-013", StrideCategory.ELEVATION_OF_PRIVILEGE,
                    Severity.CRITICAL, r,
                    f"IAM binding '{r.name}' grants the '{role}' role at project level — effectively unrestricted access.",
                    "Replace owner/editor roles with purpose-specific predefined or custom roles following least privilege.",
                    "role",
                ))

        # ----------------------------------------- KMS Key
        if rt == "google_kms_crypto_key":
            rotation = p.get("rotation_period")
            if not rotation:
                threats.append(_make(
                    "GCP-014", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.MEDIUM, r,
                    f"KMS key '{r.name}' does not have an automatic rotation period configured.",
                    "Set rotation_period to a value such as \"7776000s\" (90 days).",
                    "rotation_period",
                ))

        # ----------------------------------------- Project Metadata (OS Login)
        if rt == "google_compute_project_metadata":
            metadata = p.get("metadata", {}) or {}
            os_login = metadata.get("enable-oslogin")
            if str(os_login).upper() != "TRUE":
                threats.append(_make(
                    "GCP-015", StrideCategory.SPOOFING,
                    Severity.MEDIUM, r,
                    f"Project metadata '{r.name}' does not enforce OS Login — SSH key management is decentralised and hard to audit.",
                    "Set metadata.enable-oslogin = \"TRUE\" in google_compute_project_metadata.",
                    "metadata.enable-oslogin",
                ))

    return threats
