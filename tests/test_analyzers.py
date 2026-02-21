"""
Analyzer tests — verify STRIDE threats are detected in fixture files.
"""
import os

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _parse_all_fixtures():
    """Load resources from all fixture files."""
    from threatmap.parsers import cloudformation, kubernetes, terraform
    resources = []
    resources.extend(terraform.parse_file(os.path.join(FIXTURES, "aws_insecure.tf")))
    resources.extend(terraform.parse_file(os.path.join(FIXTURES, "azure_insecure.tf")))
    resources.extend(terraform.parse_file(os.path.join(FIXTURES, "gcp_insecure.tf")))
    resources.extend(cloudformation.parse_file(os.path.join(FIXTURES, "cfn_insecure.yaml")))
    resources.extend(kubernetes.parse_file(os.path.join(FIXTURES, "k8s_insecure.yaml")))
    return resources


def _parse_aws():
    from threatmap.parsers import terraform
    return terraform.parse_file(os.path.join(FIXTURES, "aws_insecure.tf"))


def _parse_azure():
    from threatmap.parsers import terraform
    return terraform.parse_file(os.path.join(FIXTURES, "azure_insecure.tf"))


def _parse_gcp():
    from threatmap.parsers import terraform
    return terraform.parse_file(os.path.join(FIXTURES, "gcp_insecure.tf"))


def _parse_cfn():
    from threatmap.parsers import cloudformation
    return cloudformation.parse_file(os.path.join(FIXTURES, "cfn_insecure.yaml"))


def _parse_k8s():
    from threatmap.parsers import kubernetes
    return kubernetes.parse_file(os.path.join(FIXTURES, "k8s_insecure.yaml"))


# --------------------------------------------------------- AWS Analyzer
class TestAWSAnalyzer:
    def setup_method(self):
        from threatmap.analyzers import aws
        self.analyzer = aws

    def test_s3_public_access_detected(self):
        resources = _parse_aws()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "public_access_block" in triggers

    def test_s3_encryption_detected(self):
        resources = _parse_aws()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "server_side_encryption_configuration" in triggers

    def test_sg_ssh_open_detected(self):
        resources = _parse_aws()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "ingress.ssh_rdp_open" in triggers

    def test_iam_wildcard_detected(self):
        resources = _parse_aws()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "policy.wildcard" in triggers

    def test_iam_principal_wildcard_detected(self):
        resources = _parse_aws()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "assume_role_policy.principal_wildcard" in triggers

    def test_rds_public_detected(self):
        resources = _parse_aws()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "publicly_accessible" in triggers

    def test_imdsv1_detected(self):
        resources = _parse_aws()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property or "" for t in threats]
        # Trigger is either "metadata_options" (block absent) or "metadata_options.http_tokens"
        assert any("metadata_options" in t for t in triggers)

    def test_minimum_threat_count(self):
        resources = _parse_aws()
        threats = self.analyzer.analyze(resources)
        assert len(threats) >= 10

    def test_cfn_threats_detected(self):
        resources = _parse_cfn()
        threats = self.analyzer.analyze(resources)
        assert len(threats) >= 5

    def test_cfn_s3_encryption_detected(self):
        resources = _parse_cfn()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "server_side_encryption_configuration" in triggers


# --------------------------------------------------------- Azure Analyzer
class TestAzureAnalyzer:
    def setup_method(self):
        from threatmap.analyzers import azure
        self.analyzer = azure

    def test_storage_public_blob_detected(self):
        resources = _parse_azure()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "allow_blob_public_access" in triggers

    def test_storage_tls_detected(self):
        resources = _parse_azure()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "min_tls_version" in triggers

    def test_nsg_ssh_open_detected(self):
        resources = _parse_azure()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "security_rule.ssh_rdp_open" in triggers

    def test_role_owner_detected(self):
        resources = _parse_azure()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "role_definition_name" in triggers

    def test_aks_rbac_disabled_detected(self):
        resources = _parse_azure()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "role_based_access_control_enabled" in triggers

    def test_minimum_threat_count(self):
        resources = _parse_azure()
        threats = self.analyzer.analyze(resources)
        assert len(threats) >= 10


# --------------------------------------------------------- GCP Analyzer
class TestGCPAnalyzer:
    def setup_method(self):
        from threatmap.analyzers import gcp
        self.analyzer = gcp

    def test_bucket_uniform_access_detected(self):
        resources = _parse_gcp()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "uniform_bucket_level_access" in triggers

    def test_firewall_ssh_open_detected(self):
        resources = _parse_gcp()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "allow.ports.ssh_rdp" in triggers

    def test_project_owner_role_detected(self):
        resources = _parse_gcp()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "role" in triggers

    def test_gke_master_networks_detected(self):
        resources = _parse_gcp()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "master_authorized_networks_config" in triggers

    def test_minimum_threat_count(self):
        resources = _parse_gcp()
        threats = self.analyzer.analyze(resources)
        assert len(threats) >= 8


# --------------------------------------------------------- Kubernetes Analyzer
class TestKubernetesAnalyzer:
    def setup_method(self):
        from threatmap.analyzers import kubernetes
        self.analyzer = kubernetes

    def test_privileged_container_detected(self):
        resources = _parse_k8s()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property or "" for t in threats]
        assert any("privileged" in t for t in triggers)

    def test_cluster_admin_binding_detected(self):
        resources = _parse_k8s()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "roleRef.name" in triggers

    def test_anonymous_binding_detected(self):
        resources = _parse_k8s()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "subjects.name" in triggers

    def test_ingress_no_tls_detected(self):
        resources = _parse_k8s()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "spec.tls" in triggers

    def test_configmap_secret_detected(self):
        resources = _parse_k8s()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property or "" for t in threats]
        assert any("api_key" in t or "data." in t for t in triggers)

    def test_no_network_policy_detected(self):
        resources = _parse_k8s()
        threats = self.analyzer.analyze(resources)
        triggers = [t.trigger_property for t in threats]
        assert "NetworkPolicy.missing" in triggers

    def test_minimum_threat_count(self):
        resources = _parse_k8s()
        threats = self.analyzer.analyze(resources)
        assert len(threats) >= 8


# --------------------------------------------------------- Engine
class TestEngine:
    def setup_method(self):
        from threatmap.analyzers import engine
        self.engine = engine

    def test_threat_ids_are_sequential(self):
        resources = _parse_all_fixtures()
        threats = self.engine.run(resources)
        for i, t in enumerate(threats, 1):
            assert t.threat_id == f"T-{i:03d}", f"Expected T-{i:03d}, got {t.threat_id}"

    def test_sorted_by_severity(self):
        from threatmap.models.threat import Severity
        severity_order = {s.value: i for i, s in enumerate(
            [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        )}
        resources = _parse_all_fixtures()
        threats = self.engine.run(resources)
        for i in range(len(threats) - 1):
            assert (
                severity_order[threats[i].severity.value]
                <= severity_order[threats[i + 1].severity.value]
            ), f"Severity ordering violated at position {i}"

    def test_no_duplicate_ids(self):
        resources = _parse_all_fixtures()
        threats = self.engine.run(resources)
        ids = [t.threat_id for t in threats]
        assert len(ids) == len(set(ids))

    def test_minimum_total_threat_count(self):
        resources = _parse_all_fixtures()
        threats = self.engine.run(resources)
        assert len(threats) >= 30

    def test_critical_threats_present(self):
        from threatmap.models.threat import Severity
        resources = _parse_all_fixtures()
        threats = self.engine.run(resources)
        critical = [t for t in threats if t.severity == Severity.CRITICAL]
        assert len(critical) >= 5

    def test_deduplication(self):
        """Running the engine twice on the same resources should not double threats."""
        resources = _parse_aws()
        threats_first = self.engine.run(resources)
        threats_second = self.engine.run(resources)
        assert len(threats_first) == len(threats_second)


# --------------------------------------------------------- CI Exit Code Behavior
class TestCIBehavior:
    """Test exit code logic via Click's test runner."""

    def _run_scan(self, path, extra_args=None):
        from click.testing import CliRunner
        from threatmap.cli import scan
        runner = CliRunner()
        args = [path]
        if extra_args:
            args.extend(extra_args)
        return runner.invoke(scan, args, catch_exceptions=False)

    def test_fail_on_critical_exits_1(self):
        result = self._run_scan(
            os.path.join(FIXTURES, "aws_insecure.tf"),
            ["--fail-on", "CRITICAL"],
        )
        assert result.exit_code == 1

    def test_no_fail_on_clean(self, tmp_path):
        # Write a minimal valid (clean) Terraform file
        clean = tmp_path / "clean.tf"
        clean.write_text(
            'resource "aws_kms_key" "k" { enable_key_rotation = true }\n'
        )
        result = self._run_scan(str(clean), ["--fail-on", "CRITICAL"])
        # No CRITICAL should be found — exit 0
        assert result.exit_code == 0

    def test_json_output_valid(self, tmp_path):
        """Write JSON report to a file and validate its structure."""
        import json as _json
        out = str(tmp_path / "report.json")
        result = self._run_scan(
            os.path.join(FIXTURES, "aws_insecure.tf"),
            ["--format", "json", "--output", out],
        )
        assert result.exit_code == 0
        with open(out) as fh:
            data = _json.load(fh)
        assert "threats" in data
        assert "resources" in data
        assert "summary" in data
