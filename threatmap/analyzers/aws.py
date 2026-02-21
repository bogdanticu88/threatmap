"""
AWS STRIDE rules — covers Terraform aws_* resources and CloudFormation AWS::* resources.
"""
import json
import re
from typing import Any, Dict, List, Optional

# Matches Terraform template expressions like ${jsonencode({...})}
_JSONENCODE_RE = re.compile(r'\$\{jsonencode\((.+)\)\}$', re.DOTALL)

from threatmap.models.resource import Resource
from threatmap.models.threat import Severity, StrideCategory, Threat

# Map CFN types to the equivalent Terraform type names so rules can be shared
CFN_TYPE_MAP = {
    "AWS::S3::Bucket":              "aws_s3_bucket",
    "AWS::S3::BucketPolicy":        "aws_s3_bucket_policy",
    "AWS::IAM::Role":               "aws_iam_role",
    "AWS::IAM::Policy":             "aws_iam_policy",
    "AWS::IAM::ManagedPolicy":      "aws_iam_policy",
    "AWS::EC2::SecurityGroup":      "aws_security_group",
    "AWS::RDS::DBInstance":         "aws_db_instance",
    "AWS::EKS::Cluster":            "aws_eks_cluster",
    "AWS::CloudTrail::Trail":       "aws_cloudtrail",
    "AWS::KMS::Key":                "aws_kms_key",
    "AWS::Lambda::Function":        "aws_lambda_function",
    "AWS::EC2::Instance":           "aws_instance",
}

_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
_PRIVILEGED_ROLES = {"Owner", "Contributor", "User Access Administrator"}


def _norm_type(r: Resource) -> str:
    """Return a normalised resource type for rule matching."""
    if r.source_format == "cloudformation":
        return CFN_TYPE_MAP.get(r.resource_type, r.resource_type)
    return r.resource_type


def _get(props: Dict, *keys, default=None) -> Any:
    """Drill into nested dicts safely."""
    cur = props
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
        if cur is None:
            return default
    return cur


def _cidr_open(cidr_val: Any) -> bool:
    if isinstance(cidr_val, str):
        return cidr_val in _OPEN_CIDRS
    if isinstance(cidr_val, list):
        return any(c in _OPEN_CIDRS for c in cidr_val)
    return False


def _port_in_range(from_port: Any, to_port: Any, target: int) -> bool:
    try:
        fp = int(from_port)
        tp = int(to_port)
        return fp <= target <= tp
    except (TypeError, ValueError):
        return False


def _resolve_policy(policy_val: Any) -> Any:
    """
    Normalise a policy value from various representations:
    - Plain JSON string → parsed dict
    - Terraform "${jsonencode({...})}" template string → parsed dict
    - Already a dict → returned as-is
    """
    if isinstance(policy_val, str):
        # Strip Terraform jsonencode() wrapper if present
        m = _JSONENCODE_RE.match(policy_val.strip())
        if m:
            # The inner part is already valid JSON (HCL2 serialises it that way)
            try:
                return json.loads(m.group(1))
            except Exception:
                pass
        # Try plain JSON
        try:
            return json.loads(policy_val)
        except Exception:
            pass
    return policy_val


def _policy_is_wildcard(policy_val: Any) -> bool:
    """Return True if a JSON policy document grants Action:* on Resource:*."""
    policy_val = _resolve_policy(policy_val)
    if isinstance(policy_val, str):
        return False
    if not isinstance(policy_val, dict):
        return False
    statements = policy_val.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        action = stmt.get("Action", [])
        resource = stmt.get("Resource", [])
        effect = stmt.get("Effect", "Allow")
        if effect != "Allow":
            continue
        action_list = [action] if isinstance(action, str) else action
        resource_list = [resource] if isinstance(resource, str) else resource
        if "*" in action_list and "*" in resource_list:
            return True
    return False


def _principal_is_wildcard(policy_val: Any) -> bool:
    policy_val = _resolve_policy(policy_val)
    if isinstance(policy_val, str):
        return False
    if not isinstance(policy_val, dict):
        return False
    for stmt in policy_val.get("Statement", []):
        if not isinstance(stmt, dict):
            continue
        principal = stmt.get("Principal", None)
        if principal == "*":
            return True
        if isinstance(principal, dict) and principal.get("AWS") == "*":
            return True
    return False


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
        threat_id="",   # assigned by engine
        stride_category=stride,
        severity=severity,
        resource_name=resource.name,
        resource_type=resource.resource_type,
        description=description,
        mitigation=mitigation,
        trigger_property=trigger,
    )


def analyze(resources: List[Resource]) -> List[Threat]:
    threats: List[Threat] = []

    aws_resources = [
        r for r in resources
        if r.provider == "aws" or r.source_format == "cloudformation"
    ]

    # Build a set of resource types present (for cross-resource checks)
    type_map: Dict[str, List[Resource]] = {}
    for r in aws_resources:
        nt = _norm_type(r)
        type_map.setdefault(nt, []).append(r)

    for r in aws_resources:
        p = r.properties
        nt = _norm_type(r)

        # ------------------------------------------------------------------ S3
        if nt == "aws_s3_bucket":
            # AWS-001: public access block missing or disabled
            # For Terraform we look for a companion aws_s3_bucket_public_access_block
            pab_resources = type_map.get("aws_s3_bucket_public_access_block", [])
            # Check if any PAB references this bucket
            has_pab = any(
                r.name in str(pab.properties) or r.name in pab.relationships
                for pab in pab_resources
            )
            if not has_pab:
                # CFN: check BlockPublicAcls etc. inline
                acl_block = p.get("PublicAccessBlockConfiguration") or p.get(
                    "block_public_acls"
                )
                if acl_block is None:
                    threats.append(_make(
                        "AWS-001", StrideCategory.INFORMATION_DISCLOSURE,
                        Severity.CRITICAL, r,
                        f"S3 bucket '{r.name}' has no public access block configured — bucket may be publicly accessible.",
                        "Enable S3 Block Public Access on the bucket and at the account level.",
                        "public_access_block",
                    ))

            # AWS-002: server-side encryption absent
            sse = p.get("server_side_encryption_configuration") or p.get(
                "BucketEncryption"
            )
            if sse is None:
                threats.append(_make(
                    "AWS-002", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.HIGH, r,
                    f"S3 bucket '{r.name}' does not have server-side encryption configured.",
                    "Add a server_side_encryption_configuration block using AES256 or aws:kms.",
                    "server_side_encryption_configuration",
                ))

            # AWS-003: versioning disabled or absent
            versioning = p.get("versioning") or p.get("VersioningConfiguration") or {}
            if isinstance(versioning, dict):
                enabled = versioning.get("enabled") or versioning.get("Status", "")
                if str(enabled).lower() not in ("true", "enabled"):
                    threats.append(_make(
                        "AWS-003", StrideCategory.TAMPERING,
                        Severity.MEDIUM, r,
                        f"S3 bucket '{r.name}' does not have versioning enabled — objects can be overwritten or deleted without recovery.",
                        "Enable versioning on the S3 bucket.",
                        "versioning",
                    ))
            else:
                threats.append(_make(
                    "AWS-003", StrideCategory.TAMPERING,
                    Severity.MEDIUM, r,
                    f"S3 bucket '{r.name}' does not have versioning enabled.",
                    "Enable versioning on the S3 bucket.",
                    "versioning",
                ))

            # AWS-004: logging absent
            logging_block = p.get("logging") or p.get("LoggingConfiguration")
            if logging_block is None:
                threats.append(_make(
                    "AWS-004", StrideCategory.REPUDIATION,
                    Severity.MEDIUM, r,
                    f"S3 bucket '{r.name}' does not have access logging enabled — activity cannot be audited.",
                    "Enable S3 server access logging and direct logs to a dedicated audit bucket.",
                    "logging",
                ))

        # -------------------------------------------------------- Security Group
        if nt == "aws_security_group":
            ingress_rules = p.get("ingress", []) or p.get("SecurityGroupIngress", [])
            if isinstance(ingress_rules, dict):
                ingress_rules = [ingress_rules]

            for rule in ingress_rules:
                if not isinstance(rule, dict):
                    continue
                cidrs = rule.get("cidr_blocks") or rule.get("CidrIp") or rule.get("CidrIpv6", [])
                from_port = rule.get("from_port") or rule.get("FromPort", -1)
                to_port = rule.get("to_port") or rule.get("ToPort", -1)

                if not _cidr_open(cidrs):
                    continue

                # AWS-005: any open ingress
                threats.append(_make(
                    "AWS-005", StrideCategory.SPOOFING,
                    Severity.HIGH, r,
                    f"Security group '{r.name}' allows inbound traffic from 0.0.0.0/0.",
                    "Restrict ingress rules to known CIDR ranges or security group references.",
                    "ingress.cidr_blocks",
                ))

                # AWS-006: SSH or RDP open to world
                if _port_in_range(from_port, to_port, 22) or _port_in_range(from_port, to_port, 3389):
                    threats.append(_make(
                        "AWS-006", StrideCategory.SPOOFING,
                        Severity.CRITICAL, r,
                        f"Security group '{r.name}' exposes SSH/RDP (port 22/3389) to 0.0.0.0/0.",
                        "Remove public SSH/RDP access. Use AWS Systems Manager Session Manager or a bastion host with IP restrictions.",
                        "ingress.ssh_rdp_open",
                    ))

                # AWS-007: all traffic open
                try:
                    fp = int(from_port)
                    tp = int(to_port)
                    if fp == 0 and tp == 0:
                        threats.append(_make(
                            "AWS-007", StrideCategory.DENIAL_OF_SERVICE,
                            Severity.HIGH, r,
                            f"Security group '{r.name}' allows all inbound traffic (port 0–0) from 0.0.0.0/0.",
                            "Restrict ingress to specific ports and CIDR ranges.",
                            "ingress.all_traffic",
                        ))
                except (TypeError, ValueError):
                    pass

        # --------------------------------------------------------------- IAM
        if nt in ("aws_iam_role", "aws_iam_policy"):
            # AWS-008: wildcard policy
            policy_doc = (
                p.get("policy")
                or p.get("PolicyDocument")
                or p.get("inline_policy", {}).get("policy")
            )
            if policy_doc and _policy_is_wildcard(policy_doc):
                threats.append(_make(
                    "AWS-008", StrideCategory.ELEVATION_OF_PRIVILEGE,
                    Severity.CRITICAL, r,
                    f"IAM resource '{r.name}' grants Action:* on Resource:* — effectively full admin access.",
                    "Replace wildcard actions and resources with least-privilege policy statements.",
                    "policy.wildcard",
                ))

            if nt == "aws_iam_role":
                # AWS-009: assume role policy allows any principal
                assume_policy = p.get("assume_role_policy") or p.get("AssumeRolePolicyDocument")
                if assume_policy and _principal_is_wildcard(assume_policy):
                    threats.append(_make(
                        "AWS-009", StrideCategory.ELEVATION_OF_PRIVILEGE,
                        Severity.CRITICAL, r,
                        f"IAM role '{r.name}' trust policy allows Principal:* — any entity can assume this role.",
                        "Restrict the Principal in the trust policy to specific AWS accounts, services, or roles.",
                        "assume_role_policy.principal_wildcard",
                    ))

        # --------------------------------------------------------------- RDS
        if nt == "aws_db_instance":
            # AWS-010: publicly accessible
            pub = p.get("publicly_accessible") or p.get("PubliclyAccessible")
            if str(pub).lower() == "true":
                threats.append(_make(
                    "AWS-010", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.HIGH, r,
                    f"RDS instance '{r.name}' is publicly accessible from the internet.",
                    "Set publicly_accessible = false and place the RDS instance in a private subnet.",
                    "publicly_accessible",
                ))

            # AWS-011: storage not encrypted
            enc = p.get("storage_encrypted") or p.get("StorageEncrypted")
            if str(enc).lower() not in ("true",):
                threats.append(_make(
                    "AWS-011", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.HIGH, r,
                    f"RDS instance '{r.name}' does not have storage encryption enabled.",
                    "Set storage_encrypted = true and specify a KMS key.",
                    "storage_encrypted",
                ))

            # AWS-012: deletion protection
            del_prot = p.get("deletion_protection") or p.get("DeletionProtection")
            if str(del_prot).lower() not in ("true",):
                threats.append(_make(
                    "AWS-012", StrideCategory.TAMPERING,
                    Severity.MEDIUM, r,
                    f"RDS instance '{r.name}' does not have deletion protection enabled.",
                    "Set deletion_protection = true for production databases.",
                    "deletion_protection",
                ))

            # AWS-013: backup retention
            retention = p.get("backup_retention_period") or p.get("BackupRetentionPeriod", 0)
            try:
                if int(retention) == 0:
                    threats.append(_make(
                        "AWS-013", StrideCategory.TAMPERING,
                        Severity.MEDIUM, r,
                        f"RDS instance '{r.name}' has automated backups disabled (retention period = 0).",
                        "Set backup_retention_period to at least 7 days.",
                        "backup_retention_period",
                    ))
            except (TypeError, ValueError):
                pass

        # --------------------------------------------------------------- EKS
        if nt == "aws_eks_cluster":
            vpc_config = p.get("vpc_config") or p.get("ResourcesVpcConfig") or {}
            pub_access = vpc_config.get("endpoint_public_access", True)
            pub_cidrs = vpc_config.get("public_access_cidrs", ["0.0.0.0/0"])

            if str(pub_access).lower() != "false":
                if not pub_cidrs or any(c in _OPEN_CIDRS for c in pub_cidrs):
                    threats.append(_make(
                        "AWS-014", StrideCategory.INFORMATION_DISCLOSURE,
                        Severity.HIGH, r,
                        f"EKS cluster '{r.name}' Kubernetes API is publicly accessible without CIDR restrictions.",
                        "Set endpoint_public_access = false or restrict public_access_cidrs to known CIDR ranges.",
                        "vpc_config.endpoint_public_access",
                    ))

            enc_config = p.get("encryption_config") or p.get("EncryptionConfig")
            if not enc_config:
                threats.append(_make(
                    "AWS-015", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.HIGH, r,
                    f"EKS cluster '{r.name}' does not have encryption_config defined — secrets stored unencrypted.",
                    "Configure encryption_config with a KMS key to encrypt Kubernetes secrets.",
                    "encryption_config",
                ))

        # --------------------------------------------------------- CloudTrail
        if nt == "aws_cloudtrail":
            multi = p.get("is_multi_region_trail") or p.get("IsMultiRegionTrail")
            if str(multi).lower() not in ("true",):
                threats.append(_make(
                    "AWS-016", StrideCategory.REPUDIATION,
                    Severity.HIGH, r,
                    f"CloudTrail '{r.name}' is not configured as a multi-region trail — API calls in other regions are not logged.",
                    "Set is_multi_region_trail = true.",
                    "is_multi_region_trail",
                ))

            validation = p.get("enable_log_file_validation") or p.get("EnableLogFileValidation")
            if str(validation).lower() not in ("true",):
                threats.append(_make(
                    "AWS-017", StrideCategory.TAMPERING,
                    Severity.HIGH, r,
                    f"CloudTrail '{r.name}' does not have log file validation enabled — logs may be tampered with undetected.",
                    "Set enable_log_file_validation = true.",
                    "enable_log_file_validation",
                ))

        # --------------------------------------------------------------- KMS
        if nt == "aws_kms_key":
            rotation = p.get("enable_key_rotation") or p.get("EnableKeyRotation")
            if str(rotation).lower() not in ("true",):
                threats.append(_make(
                    "AWS-018", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.MEDIUM, r,
                    f"KMS key '{r.name}' does not have automatic key rotation enabled.",
                    "Set enable_key_rotation = true.",
                    "enable_key_rotation",
                ))

        # ---------------------------------------------------------- Lambda
        if nt == "aws_lambda_function":
            # AWS-019: not in VPC
            vpc_config = p.get("vpc_config")
            if not vpc_config:
                threats.append(_make(
                    "AWS-019", StrideCategory.INFORMATION_DISCLOSURE,
                    Severity.LOW, r,
                    f"Lambda function '{r.name}' is not running inside a VPC.",
                    "Place the Lambda function inside a VPC with appropriate security groups to limit network exposure.",
                    "vpc_config",
                ))

        # ---------------------------------------------------------- EC2
        if nt == "aws_instance":
            # AWS-021: root EBS encryption
            root_block = p.get("root_block_device") or {}
            if isinstance(root_block, dict):
                encrypted = root_block.get("encrypted")
                if str(encrypted).lower() not in ("true",):
                    threats.append(_make(
                        "AWS-021", StrideCategory.INFORMATION_DISCLOSURE,
                        Severity.MEDIUM, r,
                        f"EC2 instance '{r.name}' root EBS volume is not encrypted.",
                        "Set encrypted = true in the root_block_device block, or enable EBS encryption by default in the region.",
                        "root_block_device.encrypted",
                    ))

            # AWS-022: IMDSv2 required
            metadata_opts = p.get("metadata_options") or {}
            if isinstance(metadata_opts, dict):
                http_tokens = metadata_opts.get("http_tokens", "optional")
                if str(http_tokens).lower() != "required":
                    threats.append(_make(
                        "AWS-022", StrideCategory.ELEVATION_OF_PRIVILEGE,
                        Severity.HIGH, r,
                        f"EC2 instance '{r.name}' allows IMDSv1 — metadata service is accessible without session tokens, enabling SSRF-based credential theft.",
                        "Set metadata_options { http_tokens = \"required\" } to enforce IMDSv2.",
                        "metadata_options.http_tokens",
                    ))
            else:
                # metadata_options block absent — IMDSv1 is the default
                threats.append(_make(
                    "AWS-022", StrideCategory.ELEVATION_OF_PRIVILEGE,
                    Severity.HIGH, r,
                    f"EC2 instance '{r.name}' has no metadata_options block — IMDSv1 is enabled by default.",
                    "Add metadata_options { http_tokens = \"required\" } to enforce IMDSv2.",
                    "metadata_options",
                ))

    return threats
