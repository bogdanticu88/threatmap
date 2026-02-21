"""
Azure STRIDE rules — covers Terraform azurerm_* resources.
"""
import re
from typing import Any, Dict, List, Optional

from threatmap.models.resource import Resource
from threatmap.models.threat import Severity, StrideCategory, Threat

_OPEN_PREFIXES = {"*", "0.0.0.0/0", "Internet", "Any"}
_PRIVILEGED_ROLES = {"Owner", "Contributor", "User Access Administrator"}
_SUB_SCOPE_RE = re.compile(r"/subscriptions/[^/]+$")


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


def _port_in_range(port_range: Any, target: int) -> bool:
    """Handle port ranges like '22', '22-3389', '*'."""
    if port_range is None or port_range == "*":
        return True
    s = str(port_range)
    if "-" in s:
        parts = s.split("-", 1)
        try:
            return int(parts[0]) <= target <= int(parts[1])
        except ValueError:
            return False
    try:
        return int(s) == target
    except ValueError:
        return False


def analyze(resources: List[Resource]) -> List[Threat]:
    threats: List[Threat] = []

    azure_resources = [r for r in resources if r.provider == "azure"]

    for r in azure_resources:
        p = r.properties
        rt = r.resource_type

        # ------------------------------------------------ Storage Account
        if rt == "azurerm_storage_account":
            # AZ-001: public blob access
            pub = p.get("allow_blob_public_access") or p.get("allow_nested_items_to_be_public")
            if str(pub).lower() == "true":
                threats.append(_make(
                    "AZ-001", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.CRITICAL, r,
                    f"Storage account '{r.name}' allows public blob access — any unauthenticated user can read blob data.",
                    "Set allow_blob_public_access = false.",
                    "allow_blob_public_access",
                ))

            # AZ-002: TLS version
            min_tls = p.get("min_tls_version", "")
            if str(min_tls) != "TLS1_2":
                threats.append(_make(
                    "AZ-002", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.HIGH, r,
                    f"Storage account '{r.name}' does not enforce TLS 1.2 — data in transit may be intercepted.",
                    "Set min_tls_version = \"TLS1_2\".",
                    "min_tls_version",
                ))

            # AZ-003: HTTPS only
            https_only = p.get("enable_https_traffic_only", True)
            if str(https_only).lower() == "false":
                threats.append(_make(
                    "AZ-003", StrideCategory.TAMPERING,
                    Severity.HIGH, r,
                    f"Storage account '{r.name}' allows unencrypted HTTP traffic.",
                    "Set enable_https_traffic_only = true.",
                    "enable_https_traffic_only",
                ))

            # AZ-004: network rules
            net_rules = p.get("network_rules")
            if not net_rules:
                threats.append(_make(
                    "AZ-004", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.MEDIUM, r,
                    f"Storage account '{r.name}' has no network_rules block — access is unrestricted by network.",
                    "Add a network_rules block with default_action = \"Deny\" and whitelist specific subnets or IPs.",
                    "network_rules",
                ))
            elif isinstance(net_rules, dict):
                if str(net_rules.get("default_action", "Allow")).lower() == "allow":
                    threats.append(_make(
                        "AZ-004", StrideCategory.INFORMATION_DISCLOSURE,
                        Severity.MEDIUM, r,
                        f"Storage account '{r.name}' network_rules defaults to Allow — storage is reachable from any network.",
                        "Change network_rules.default_action to \"Deny\".",
                        "network_rules.default_action",
                    ))

        # ------------------------------------------------ Key Vault
        if rt == "azurerm_key_vault":
            # AZ-005: purge protection
            purge = p.get("purge_protection_enabled")
            if str(purge).lower() not in ("true",):
                threats.append(_make(
                    "AZ-005", StrideCategory.TAMPERING,
                    Severity.HIGH, r,
                    f"Key Vault '{r.name}' does not have purge protection enabled — secrets can be permanently deleted.",
                    "Set purge_protection_enabled = true.",
                    "purge_protection_enabled",
                ))

            # AZ-006: network ACLs
            net_acls = p.get("network_acls")
            if not net_acls:
                threats.append(_make(
                    "AZ-006", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.MEDIUM, r,
                    f"Key Vault '{r.name}' has no network_acls block — accessible from any network.",
                    "Add a network_acls block with default_action = \"Deny\".",
                    "network_acls",
                ))
            elif isinstance(net_acls, dict):
                if str(net_acls.get("default_action", "Allow")).lower() == "allow":
                    threats.append(_make(
                        "AZ-006", StrideCategory.INFORMATION_DISCLOSURE,
                        Severity.MEDIUM, r,
                        f"Key Vault '{r.name}' network ACL defaults to Allow.",
                        "Set network_acls.default_action = \"Deny\".",
                        "network_acls.default_action",
                    ))

        # ----------------------------------------- Network Security Group
        if rt == "azurerm_network_security_group":
            rules = p.get("security_rule", [])
            if isinstance(rules, dict):
                rules = [rules]
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                direction = str(rule.get("direction", "")).lower()
                if direction != "inbound":
                    continue
                action = str(rule.get("access", "Allow")).lower()
                if action != "allow":
                    continue
                src = rule.get("source_address_prefix", "")
                dest_port = rule.get("destination_port_range")
                if str(src) in _OPEN_PREFIXES:
                    # AZ-007: open inbound
                    threats.append(_make(
                        "AZ-007", StrideCategory.SPOOFING,
                        Severity.HIGH, r,
                        f"NSG '{r.name}' has an inbound Allow rule from {src}.",
                        "Restrict source_address_prefix to known CIDR ranges.",
                        "security_rule.source_address_prefix",
                    ))
                    # AZ-008: SSH/RDP
                    if _port_in_range(dest_port, 22) or _port_in_range(dest_port, 3389):
                        threats.append(_make(
                            "AZ-008", StrideCategory.SPOOFING,
                            Severity.CRITICAL, r,
                            f"NSG '{r.name}' exposes SSH/RDP (port 22/3389) to the internet.",
                            "Remove public SSH/RDP access. Use Azure Bastion or JIT VM access.",
                            "security_rule.ssh_rdp_open",
                        ))

        # -------------------------------------------- Role Assignment
        if rt == "azurerm_role_assignment":
            role_name = p.get("role_definition_name", "")
            scope = p.get("scope", "")

            if role_name in _PRIVILEGED_ROLES:
                threats.append(_make(
                    "AZ-009", StrideCategory.ELEVATION_OF_PRIVILEGE,
                    Severity.CRITICAL, r,
                    f"Role assignment '{r.name}' grants the privileged role '{role_name}'.",
                    "Avoid Owner, Contributor, and User Access Administrator at broad scopes. Use purpose-built custom roles.",
                    "role_definition_name",
                ))

            if role_name in _PRIVILEGED_ROLES and _SUB_SCOPE_RE.search(str(scope)):
                threats.append(_make(
                    "AZ-010", StrideCategory.ELEVATION_OF_PRIVILEGE,
                    Severity.HIGH, r,
                    f"Role assignment '{r.name}' grants '{role_name}' at subscription scope.",
                    "Restrict role assignments to resource group or resource scope where possible.",
                    "scope",
                ))

        # -------------------------------------------- Web Apps
        if rt in ("azurerm_linux_web_app", "azurerm_windows_web_app"):
            https_only = p.get("https_only")
            if str(https_only).lower() not in ("true",):
                threats.append(_make(
                    "AZ-011", StrideCategory.TAMPERING,
                    Severity.HIGH, r,
                    f"App Service '{r.name}' does not enforce HTTPS-only traffic.",
                    "Set https_only = true.",
                    "https_only",
                ))

            if rt == "azurerm_linux_web_app":
                identity = p.get("identity")
                if not identity:
                    threats.append(_make(
                        "AZ-012", StrideCategory.ELEVATION_OF_PRIVILEGE,
                        Severity.MEDIUM, r,
                        f"App Service '{r.name}' has no managed identity configured — it may use stored credentials instead.",
                        "Add an identity block with type = \"SystemAssigned\" and use it for downstream resource access.",
                        "identity",
                    ))

        # ------------------------------------------- AKS
        if rt == "azurerm_kubernetes_cluster":
            rbac = p.get("role_based_access_control_enabled")
            if str(rbac).lower() == "false":
                threats.append(_make(
                    "AZ-013", StrideCategory.ELEVATION_OF_PRIVILEGE,
                    Severity.CRITICAL, r,
                    f"AKS cluster '{r.name}' has RBAC disabled — any authenticated user has full cluster access.",
                    "Set role_based_access_control_enabled = true and integrate with Azure AD.",
                    "role_based_access_control_enabled",
                ))

            api_cidrs = p.get("api_server_authorized_ip_ranges")
            if not api_cidrs:
                threats.append(_make(
                    "AZ-014", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.HIGH, r,
                    f"AKS cluster '{r.name}' does not restrict API server access by IP — the Kubernetes API is publicly reachable.",
                    "Set api_server_authorized_ip_ranges to the CIDR ranges of your management network.",
                    "api_server_authorized_ip_ranges",
                ))

        # ------------------------------------------- Container Registry
        if rt == "azurerm_container_registry":
            admin = p.get("admin_enabled")
            if str(admin).lower() == "true":
                threats.append(_make(
                    "AZ-015", StrideCategory.ELEVATION_OF_PRIVILEGE,
                    Severity.HIGH, r,
                    f"Container registry '{r.name}' has the admin user enabled — shared static credentials with full registry access.",
                    "Disable admin_enabled and use managed identities or service principals with role-based access.",
                    "admin_enabled",
                ))

        # ------------------------------------------- SQL Server
        if rt == "azurerm_mssql_server":
            pub_access = p.get("public_network_access_enabled")
            if pub_access is None or str(pub_access).lower() != "false":
                threats.append(_make(
                    "AZ-016", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.HIGH, r,
                    f"SQL Server '{r.name}' has public network access enabled — the database endpoint is internet-reachable.",
                    "Set public_network_access_enabled = false and use private endpoints.",
                    "public_network_access_enabled",
                ))

        # ------------------------------------------- Linux VM
        if rt == "azurerm_linux_virtual_machine":
            disable_pwd = p.get("disable_password_authentication")
            if str(disable_pwd).lower() != "true":
                threats.append(_make(
                    "AZ-018", StrideCategory.SPOOFING,
                    Severity.HIGH, r,
                    f"Linux VM '{r.name}' allows password authentication — susceptible to brute-force attacks.",
                    "Set disable_password_authentication = true and use SSH keys.",
                    "disable_password_authentication",
                ))

        # ------------------------------------------- SQL Database
        if rt == "azurerm_mssql_database":
            tde = p.get("transparent_data_encryption_enabled")
            if tde is None or str(tde).lower() != "true":
                threats.append(_make(
                    "AZ-019", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.HIGH, r,
                    f"SQL Database '{r.name}' does not have Transparent Data Encryption enabled.",
                    "Set transparent_data_encryption_enabled = true.",
                    "transparent_data_encryption_enabled",
                ))

    return threats
