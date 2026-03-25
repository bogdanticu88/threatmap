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


    def test_s3_mfa_delete_rule(self):
        from threatmap.parsers import terraform
        resources = terraform.parse_file(os.path.join(FIXTURES, "s3_mfa_delete.tf"))
        threats = self.analyzer.analyze(resources)
        assert any(
            t.trigger_property == "versioning.mfa_delete"
            for t in threats
        )


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


# --------------------------------------------------------- MITRE ATT&CK Tests
class TestMitreAnalyzer:
    """Test MITRE ATT&CK framework analyzer."""

    def setup_method(self):
        from threatmap.analyzers import mitre
        self.analyzer = mitre

    def test_iam_no_mfa_detected(self):
        from threatmap.models.resource import Resource
        r = Resource(
            provider="aws",
            resource_type="aws_iam_user",
            name="no_mfa_user",
            properties={"mfa_enabled": False},
            source_format="terraform",
        )
        threats = self.analyzer.analyze([r])
        assert any(t.trigger_property == "mfa_enabled" for t in threats)

    def test_public_s3_exfiltration_detected(self):
        from threatmap.models.resource import Resource
        r = Resource(
            provider="aws",
            resource_type="aws_s3_bucket",
            name="public_bucket",
            properties={"public_access_block": None},
            exposure="public",
            source_format="terraform",
        )
        threats = self.analyzer.analyze([r])
        assert any(t.trigger_property == "public_access_block" for t in threats)

    def test_no_logging_defense_evasion_detected(self):
        from threatmap.models.resource import Resource
        r = Resource(
            provider="aws",
            resource_type="aws_cloudtrail",
            name="trail",
            properties={"enable_log_file_validation": False},
            source_format="terraform",
        )
        threats = self.analyzer.analyze([r])
        assert any(t.trigger_property == "logging_enabled" for t in threats)

    def test_iam_wildcard_persistence_detected(self):
        from threatmap.models.resource import Resource
        r = Resource(
            provider="aws",
            resource_type="aws_iam_policy",
            name="wild_policy",
            properties={"policy.wildcard": True},
            source_format="terraform",
        )
        threats = self.analyzer.analyze([r])
        assert any(t.trigger_property == "policy.wildcard" for t in threats)

    def test_container_as_root_priv_esc_detected(self):
        from threatmap.models.resource import Resource
        r = Resource(
            provider="kubernetes",
            resource_type="Deployment",
            name="root_deploy",
            properties={"run_as_user": 0},
            source_format="kubernetes",
        )
        threats = self.analyzer.analyze([r])
        assert any(t.trigger_property == "run_as_user" for t in threats)

    def test_unencrypted_storage_collection_detected(self):
        from threatmap.models.resource import Resource
        r = Resource(
            provider="aws",
            resource_type="aws_ebs_volume",
            name="unenc_vol",
            properties={"encrypted": False},
            source_format="terraform",
        )
        threats = self.analyzer.analyze([r])
        assert any(t.trigger_property == "encrypted" for t in threats)

    def test_mitre_ttps_populated(self):
        """All MITRE threats must carry at least one TTP."""
        resources = _parse_aws()
        threats = self.analyzer.analyze(resources)
        assert len(threats) >= 1
        for t in threats:
            assert t.mitre_ttps is not None and len(t.mitre_ttps) > 0

    def test_resource_type_aware_ttps(self):
        """Public exposure on S3 should include T1530 from resource-type lookup."""
        from threatmap.models.resource import Resource
        r = Resource(
            provider="aws",
            resource_type="aws_s3_bucket",
            name="pub",
            properties={},
            exposure="public",
            source_format="terraform",
        )
        threats = self.analyzer.analyze([r])
        all_technique_ids = [
            ttp.technique_id
            for t in threats
            for ttp in (t.mitre_ttps or [])
        ]
        assert "T1530" in all_technique_ids


# --------------------------------------------------------- PASTA Framework Tests
class TestPastaAnalyzer:
    """Test PASTA framework analyzer."""

    def setup_method(self):
        from threatmap.analyzers import pasta
        self.analyzer = pasta

    def test_supply_chain_actor_for_container(self):
        from threatmap.models.resource import Resource
        r = Resource(
            provider="kubernetes",
            resource_type="Deployment",
            name="api",
            properties={},
            source_format="kubernetes",
        )
        from threatmap.analyzers.pasta import _determine_threat_actor
        assert _determine_threat_actor(r) == "supply_chain"

    def test_misconfiguration_actor_for_storage(self):
        from threatmap.models.resource import Resource
        from threatmap.analyzers.pasta import _determine_threat_actor
        r = Resource(
            provider="aws",
            resource_type="aws_s3_bucket",
            name="bucket",
            properties={},
            exposure="unknown",
            source_format="terraform",
        )
        assert _determine_threat_actor(r) == "misconfiguration"

    def test_external_actor_for_public_resource(self):
        from threatmap.models.resource import Resource
        from threatmap.analyzers.pasta import _determine_threat_actor
        r = Resource(
            provider="aws",
            resource_type="aws_rds_instance",
            name="db",
            properties={},
            exposure="public",
            source_format="terraform",
        )
        assert _determine_threat_actor(r) == "external"

    def test_pasta_element_asset_for_public_data(self):
        from threatmap.models.resource import Resource
        from threatmap.models.threat import PastaElement
        r = Resource(
            provider="aws",
            resource_type="aws_s3_bucket",
            name="public_bucket",
            properties={"encrypted": False},
            exposure="public",
            source_format="terraform",
        )
        threats = self.analyzer.analyze([r])
        asset_threats = [
            t for t in threats
            if t.pasta_threat and t.pasta_threat.element == PastaElement.ASSET.value
        ]
        assert len(asset_threats) > 0

    def test_pasta_element_vulnerability_for_misconfiguration(self):
        from threatmap.models.resource import Resource
        from threatmap.models.threat import PastaElement
        r = Resource(
            provider="aws",
            resource_type="aws_iam_user",
            name="no_mfa",
            properties={"mfa_enabled": False},
            source_format="terraform",
        )
        threats = self.analyzer.analyze([r])
        vuln_threats = [
            t for t in threats
            if t.pasta_threat and t.pasta_threat.element == PastaElement.VULNERABILITY.value
        ]
        assert len(vuln_threats) > 0

    def test_service_disruption_scenario(self):
        from threatmap.models.resource import Resource
        r = Resource(
            provider="aws",
            resource_type="aws_cloudtrail",
            name="trail",
            properties={"logging_enabled": False},
            source_format="terraform",
        )
        threats = self.analyzer.analyze([r])
        scenarios = [t.pasta_threat.scenario for t in threats if t.pasta_threat]
        assert "service_disruption" in scenarios

    def test_infrastructure_asset_type_rules_fire(self):
        from threatmap.models.resource import Resource
        r = Resource(
            provider="aws",
            resource_type="aws_cloudtrail",
            name="trail",
            properties={"enable_log_file_validation": False},
            source_format="terraform",
        )
        threats = self.analyzer.analyze([r])
        assert len(threats) >= 1

    def test_network_policy_missing_detected(self):
        from threatmap.models.resource import Resource
        r = Resource(
            provider="kubernetes",
            resource_type="Namespace",
            name="insecure-ns",
            properties={"has_network_policy": False},
            source_format="kubernetes",
        )
        threats = self.analyzer.analyze([r])
        assert any(t.trigger_property == "NetworkPolicy.missing" for t in threats)

    def test_minimum_rule_count(self):
        resources = _parse_all_fixtures()
        threats = self.analyzer.analyze(resources)
        assert len(threats) >= 3


# --------------------------------------------------------- GraphQL API Tests
class TestGraphQL:
    """Integration tests for the GraphQL endpoint."""

    def setup_method(self):
        from fastapi.testclient import TestClient
        from threatmap.api import app
        self.client = TestClient(app)

    def test_health_query(self):
        response = self.client.post(
            "/graphql",
            json={"query": "{ health }"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["health"] == "ok"

    def test_version_query(self):
        from threatmap import __version__
        response = self.client.post(
            "/graphql",
            json={"query": "{ version }"},
        )
        assert response.status_code == 200
        assert response.json()["data"]["version"] == __version__

    def test_rules_query(self):
        response = self.client.post(
            "/graphql",
            json={"query": "{ rules }"},
        )
        assert response.status_code == 200
        rules = response.json()["data"]["rules"]
        assert "frameworks" in rules

    def test_analyze_mutation_stride(self):
        tf_content = 'resource "aws_s3_bucket" "b" { bucket = "test" }'
        escaped_content = tf_content.replace('"', '\\"')
        query = f'mutation {{ analyze(content: "{escaped_content}", filename: "test.tf", framework: "stride") {{ framework threatCount threats {{ threatId }} }} }}'
        response = self.client.post("/graphql", json={"query": query})
        assert response.status_code == 200

    def test_rest_threat_response_includes_stride_category(self):
        """Confirm REST endpoint also returns stride_category after fix."""
        tf_content = 'resource "aws_s3_bucket" "b" { bucket = "test" }'
        response = self.client.post(
            "/analyze",
            json={"content": tf_content, "filename": "test.tf", "framework": "stride"}
        )
        assert response.status_code == 200
        threats = response.json()["threats"]
        if threats:
            assert "stride_category" in threats[0]
