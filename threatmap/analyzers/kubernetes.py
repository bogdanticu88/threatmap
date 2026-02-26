"""
Kubernetes STRIDE rules.
"""
import re
from typing import Any, Dict, List, Optional

from threatmap.models.resource import Resource
from threatmap.models.threat import Severity, StrideCategory, Threat

_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Pod"}
_DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "ALL"}
_SECRET_KEY_RE = re.compile(
    r"(password|secret|token|api_key|private_key|apikey|api-key|passwd)",
    re.IGNORECASE,
)


def _make(
    rule_id: str,
    stride: StrideCategory,
    severity: Severity,
    resource: Resource,
    description: str,
    mitigation: str,
    trigger: Optional[str] = None,
    remediation: Optional[str] = None,
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
        remediation=remediation,
    )


def _get_containers(resource: Resource) -> List[Dict]:
    """
    Extract containers from workload specs.
    Handles Deployment/StatefulSet/DaemonSet (spec.template.spec.containers)
    and Pod (spec.containers).
    """
    props = resource.properties
    spec = props.get("spec", {}) or {}
    kind = resource.resource_type

    if kind == "Pod":
        containers = spec.get("containers", []) or []
        init_containers = spec.get("initContainers", []) or []
    else:
        template = spec.get("template", {}) or {}
        pod_spec = template.get("spec", {}) or {}
        containers = pod_spec.get("containers", []) or []
        init_containers = pod_spec.get("initContainers", []) or []

    result = []
    if isinstance(containers, list):
        result.extend(containers)
    if isinstance(init_containers, list):
        result.extend(init_containers)
    return result


def _get_pod_spec(resource: Resource) -> Dict:
    props = resource.properties
    spec = props.get("spec", {}) or {}
    if resource.resource_type == "Pod":
        return spec
    template = spec.get("template", {}) or {}
    return template.get("spec", {}) or {}


def _sc_bool(val: Any) -> Optional[bool]:
    """Parse a security context boolean value."""
    if isinstance(val, bool):
        return val
    if str(val).lower() == "true":
        return True
    if str(val).lower() == "false":
        return False
    return None


def analyze(resources: List[Resource]) -> List[Threat]:
    threats: List[Threat] = []

    k8s_resources = [r for r in resources if r.provider == "kubernetes"]

    # Pre-collect all NetworkPolicy resources for namespace checks
    network_policies = [r for r in k8s_resources if r.resource_type == "NetworkPolicy"]

    for r in k8s_resources:
        p = r.properties
        kind = r.resource_type
        spec = p.get("spec", {}) or {}

        # ---------------------------------- Workload rules
        if kind in _WORKLOAD_KINDS:
            pod_spec = _get_pod_spec(r)
            containers = _get_containers(r)

            for container in containers:
                if not isinstance(container, dict):
                    continue
                cname = container.get("name", "unknown")
                sc = container.get("securityContext", {}) or {}

                # K8S-001: privileged
                if _sc_bool(sc.get("privileged")) is True:
                    threats.append(_make(
                        "K8S-001", StrideCategory.ELEVATION_OF_PRIVILEGE,
                        Severity.CRITICAL, r,
                        f"Container '{cname}' in {kind} '{r.name}' runs as privileged — full host kernel access.",
                        "Remove privileged: true. Use specific capabilities instead.",
                        f"spec.containers[{cname}].securityContext.privileged",
                        "securityContext:\n  privileged: false"
                    ))

                # K8S-004: running as root
                run_as_user = sc.get("runAsUser")
                run_as_non_root = sc.get("runAsNonRoot")
                if run_as_user == 0 or _sc_bool(run_as_non_root) is not True:
                    threats.append(_make(
                        "K8S-004", StrideCategory.ELEVATION_OF_PRIVILEGE,
                        Severity.HIGH, r,
                        f"Container '{cname}' in {kind} '{r.name}' may run as root (no runAsNonRoot=true or runAsUser=0).",
                        "Set securityContext.runAsNonRoot = true and securityContext.runAsUser to a non-zero UID.",
                        f"spec.containers[{cname}].securityContext.runAsNonRoot",
                        "securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000"
                    ))

                # K8S-005: no resource limits
                resources_field = container.get("resources", {}) or {}
                if not resources_field.get("limits"):
                    threats.append(_make(
                        "K8S-005", StrideCategory.DENIAL_OF_SERVICE,
                        Severity.MEDIUM, r,
                        f"Container '{cname}' in {kind} '{r.name}' has no resource limits — a misbehaving container can exhaust node resources.",
                        "Set resources.limits.cpu and resources.limits.memory.",
                        f"spec.containers[{cname}].resources.limits",
                    ))

                # K8S-006: readOnlyRootFilesystem
                if _sc_bool(sc.get("readOnlyRootFilesystem")) is not True:
                    threats.append(_make(
                        "K8S-006", StrideCategory.TAMPERING,
                        Severity.MEDIUM, r,
                        f"Container '{cname}' in {kind} '{r.name}' does not enforce a read-only root filesystem.",
                        "Set securityContext.readOnlyRootFilesystem = true. Mount writable volumes only where needed.",
                        f"spec.containers[{cname}].securityContext.readOnlyRootFilesystem",
                    ))

                # K8S-007: allowPrivilegeEscalation
                if _sc_bool(sc.get("allowPrivilegeEscalation")) is not False:
                    threats.append(_make(
                        "K8S-007", StrideCategory.ELEVATION_OF_PRIVILEGE,
                        Severity.HIGH, r,
                        f"Container '{cname}' in {kind} '{r.name}' does not set allowPrivilegeEscalation=false.",
                        "Set securityContext.allowPrivilegeEscalation = false.",
                        f"spec.containers[{cname}].securityContext.allowPrivilegeEscalation",
                    ))

                # K8S-008: dangerous capabilities
                caps = sc.get("capabilities", {}) or {}
                added = caps.get("add", []) or []
                if isinstance(added, list):
                    dangerous = [c for c in added if c in _DANGEROUS_CAPS]
                    if dangerous:
                        threats.append(_make(
                            "K8S-008", StrideCategory.ELEVATION_OF_PRIVILEGE,
                            Severity.CRITICAL, r,
                            f"Container '{cname}' in {kind} '{r.name}' adds dangerous capabilities: {', '.join(dangerous)}.",
                            "Remove dangerous capabilities. Drop ALL and add only what is strictly required.",
                            f"spec.containers[{cname}].securityContext.capabilities.add",
                        ))

            # K8S-002: hostNetwork
            if _sc_bool(pod_spec.get("hostNetwork")) is True:
                threats.append(_make(
                    "K8S-002", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.HIGH, r,
                    f"{kind} '{r.name}' uses the host network namespace — pod can sniff all node traffic.",
                    "Remove hostNetwork: true unless absolutely required (e.g., CNI daemonsets).",
                    "spec.hostNetwork",
                ))

            # K8S-003: hostPID / hostIPC
            if _sc_bool(pod_spec.get("hostPID")) is True or _sc_bool(pod_spec.get("hostIPC")) is True:
                threats.append(_make(
                    "K8S-003", StrideCategory.ELEVATION_OF_PRIVILEGE,
                    Severity.HIGH, r,
                    f"{kind} '{r.name}' uses host PID or IPC namespace — container can interact with host processes.",
                    "Remove hostPID: true and hostIPC: true.",
                    "spec.hostPID_or_hostIPC",
                ))

            # K8S-009: automountServiceAccountToken
            if kind in ("Deployment", "Pod"):
                auto_mount = pod_spec.get("automountServiceAccountToken")
                if _sc_bool(auto_mount) is not False:
                    threats.append(_make(
                        "K8S-009", StrideCategory.ELEVATION_OF_PRIVILEGE,
                        Severity.MEDIUM, r,
                        f"{kind} '{r.name}' does not explicitly disable automountServiceAccountToken — the SA token is mounted by default.",
                        "Set automountServiceAccountToken: false in the pod spec if the application does not need API access.",
                        "spec.automountServiceAccountToken",
                    ))

        # ---------------------------------- ClusterRoleBinding rules
        # Note: roleRef and subjects are at the document root for RBAC resources,
        # not nested inside spec. We read from `p` (the full document) directly.
        if kind == "ClusterRoleBinding":
            role_ref = p.get("roleRef", {}) or {}
            if role_ref.get("name") == "cluster-admin":
                threats.append(_make(
                    "K8S-010", StrideCategory.ELEVATION_OF_PRIVILEGE,
                    Severity.CRITICAL, r,
                    f"ClusterRoleBinding '{r.name}' grants the cluster-admin role — unrestricted access to all cluster resources.",
                    "Use a scoped ClusterRole or RoleBinding instead of cluster-admin.",
                    "roleRef.name",
                ))

            subjects = p.get("subjects", []) or []
            for subject in subjects:
                if not isinstance(subject, dict):
                    continue
                name = subject.get("name", "")
                if name in ("system:unauthenticated", "system:anonymous"):
                    threats.append(_make(
                        "K8S-012", StrideCategory.SPOOFING,
                        Severity.CRITICAL, r,
                        f"ClusterRoleBinding '{r.name}' grants permissions to {name} — unauthenticated users have cluster access.",
                        "Remove system:unauthenticated and system:anonymous from all role bindings.",
                        "subjects.name",
                    ))

        # ---------------------------------- RoleBinding anonymous subjects
        if kind == "RoleBinding":
            subjects = p.get("subjects", []) or []
            for subject in subjects:
                if not isinstance(subject, dict):
                    continue
                name = subject.get("name", "")
                if name in ("system:unauthenticated", "system:anonymous"):
                    threats.append(_make(
                        "K8S-012", StrideCategory.SPOOFING,
                        Severity.CRITICAL, r,
                        f"RoleBinding '{r.name}' grants permissions to {name}.",
                        "Remove system:unauthenticated and system:anonymous from all role bindings.",
                        "subjects.name",
                    ))

        # ---------------------------------- ClusterRole / Role wildcard
        # rules is at the document root for ClusterRole/Role
        if kind in ("ClusterRole", "Role"):
            rules = p.get("rules", []) or spec.get("rules", []) or []
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                verbs = rule.get("verbs", []) or []
                rule_resources = rule.get("resources", []) or []
                if "*" in verbs and "*" in rule_resources:
                    threats.append(_make(
                        "K8S-011", StrideCategory.ELEVATION_OF_PRIVILEGE,
                        Severity.HIGH, r,
                        f"{kind} '{r.name}' grants wildcard verbs on wildcard resources — effectively cluster-admin.",
                        "Replace wildcard rules with explicit verb and resource lists following least privilege.",
                        "rules.verbs",
                    ))
                    break

        # ---------------------------------- Service exposure
        if kind == "Service":
            svc_type = spec.get("type", "ClusterIP")
            if svc_type in ("NodePort", "LoadBalancer"):
                threats.append(_make(
                    "K8S-013", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.MEDIUM, r,
                    f"Service '{r.name}' is of type {svc_type} — may expose pods directly to external traffic without access controls.",
                    "Use an Ingress controller with TLS and authentication instead of directly exposing NodePort/LoadBalancer services. Add annotations to restrict load balancer source IP ranges.",
                    "spec.type",
                ))

        # ---------------------------------- Ingress TLS
        if kind == "Ingress":
            tls = spec.get("tls")
            if not tls:
                threats.append(_make(
                    "K8S-014", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.HIGH, r,
                    f"Ingress '{r.name}' has no TLS configuration — traffic is served over HTTP.",
                    "Add a tls block referencing a TLS Secret and configure the Ingress to redirect HTTP to HTTPS.",
                    "spec.tls",
                ))

        # ---------------------------------- ConfigMap secret data
        if kind == "ConfigMap":
            data = p.get("data", {}) or {}
            if isinstance(data, dict):
                for key in data.keys():
                    if _SECRET_KEY_RE.search(key):
                        threats.append(_make(
                            "K8S-016", StrideCategory.INFORMATION_DISCLOSURE,
                            Severity.HIGH, r,
                            f"ConfigMap '{r.name}' contains a key '{key}' that looks like a secret — credentials should not be stored in ConfigMaps.",
                            "Move sensitive values to a Kubernetes Secret or use an external secret manager (e.g., External Secrets Operator, Vault Agent).",
                            f"data.{key}",
                        ))

        # ---------------------------------- ServiceAccount auto-mount
        if kind == "ServiceAccount":
            auto_mount = p.get("automountServiceAccountToken")
            if _sc_bool(auto_mount) is True:
                threats.append(_make(
                    "K8S-017", StrideCategory.ELEVATION_OF_PRIVILEGE,
                    Severity.MEDIUM, r,
                    f"ServiceAccount '{r.name}' has automountServiceAccountToken = true — token is automatically mounted in all pods using this SA.",
                    "Set automountServiceAccountToken: false on the ServiceAccount and enable it per-pod only where needed.",
                    "automountServiceAccountToken",
                ))

    # ---------------------------------- Namespace: no NetworkPolicy
    namespaces = [r for r in k8s_resources if r.resource_type == "Namespace"]
    # If no Namespace resources declared, check globally
    if not namespaces and not network_policies:
        # Create a synthetic threat if there are workloads and no policies
        workloads = [r for r in k8s_resources if r.resource_type in _WORKLOAD_KINDS]
        if workloads:
            # Use the first workload as the anchor resource
            ref = workloads[0]
            threats.append(Threat(
                threat_id="",
                stride_category=StrideCategory.TAMPERING,
                severity=Severity.HIGH,
                resource_name="(cluster)",
                resource_type="Namespace",
                description="No NetworkPolicy resources found — all pods can communicate with each other without restriction.",
                mitigation="Create NetworkPolicy resources in each namespace to restrict pod-to-pod traffic using a default-deny-ingress policy.",
                trigger_property="NetworkPolicy.missing",
            ))

    for ns in namespaces:
        ns_name = ns.name
        has_policy = any(
            p.properties.get("metadata", {}).get("namespace") == ns_name
            or ns_name == "default"
            for p in network_policies
        )
        if not has_policy:
            threats.append(_make(
                "K8S-015", StrideCategory.TAMPERING,
                Severity.HIGH, ns,
                f"Namespace '{ns_name}' has no NetworkPolicy — pods in this namespace can communicate freely.",
                "Create a default-deny NetworkPolicy in the namespace and explicitly allow only required traffic.",
                "NetworkPolicy.missing",
            ))

    return threats
