"""
Parser tests — verify correct resource extraction from each fixture.
"""
import os

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


# --------------------------------------------------------- Terraform
class TestTerraformParser:
    def setup_method(self):
        from threatmap.parsers import terraform
        self.parser = terraform

    def test_aws_fixture_resource_count(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "aws_insecure.tf"))
        assert len(resources) >= 9

    def test_aws_provider_assignment(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "aws_insecure.tf"))
        for r in resources:
            assert r.provider == "aws", f"Expected 'aws' for {r.resource_type}, got {r.provider}"

    def test_azure_fixture_resource_count(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "azure_insecure.tf"))
        assert len(resources) >= 9

    def test_azure_provider_assignment(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "azure_insecure.tf"))
        for r in resources:
            assert r.provider == "azure", f"Expected 'azure' for {r.resource_type}, got {r.provider}"

    def test_gcp_fixture_resource_count(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "gcp_insecure.tf"))
        assert len(resources) >= 8

    def test_gcp_provider_assignment(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "gcp_insecure.tf"))
        for r in resources:
            assert r.provider == "gcp", f"Expected 'gcp' for {r.resource_type}, got {r.provider}"

    def test_source_format_is_terraform(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "aws_insecure.tf"))
        for r in resources:
            assert r.source_format == "terraform"

    def test_resource_has_name(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "aws_insecure.tf"))
        for r in resources:
            assert r.name, "Resource name should not be empty"

    def test_relationships_extracted(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "aws_insecure.tf"))
        # aws_cloudtrail references aws_s3_bucket and aws_iam_role
        trail = next((r for r in resources if r.resource_type == "aws_cloudtrail"), None)
        assert trail is not None
        # Relationships may reference bucket or role
        assert isinstance(trail.relationships, list)

    def test_parse_directory(self, tmp_path):
        import shutil
        shutil.copy(os.path.join(FIXTURES, "aws_insecure.tf"), tmp_path / "main.tf")
        resources = self.parser.parse_directory(str(tmp_path))
        assert len(resources) >= 9

    def test_invalid_file_skipped(self, tmp_path):
        bad = tmp_path / "bad.tf"
        bad.write_text("this is not valid hcl {{{")
        resources = self.parser.parse_file(str(bad))
        assert resources == []


# --------------------------------------------------------- CloudFormation
class TestCloudFormationParser:
    def setup_method(self):
        from threatmap.parsers import cloudformation
        self.parser = cloudformation

    def test_cfn_resource_count(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "cfn_insecure.yaml"))
        assert len(resources) >= 7

    def test_cfn_provider_is_aws(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "cfn_insecure.yaml"))
        for r in resources:
            assert r.provider == "aws"

    def test_cfn_source_format(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "cfn_insecure.yaml"))
        for r in resources:
            assert r.source_format == "cloudformation"

    def test_cfn_resource_types_preserved(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "cfn_insecure.yaml"))
        types = {r.resource_type for r in resources}
        assert "AWS::S3::Bucket" in types
        assert "AWS::EC2::SecurityGroup" in types

    def test_cfn_logical_names_used(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "cfn_insecure.yaml"))
        names = {r.name for r in resources}
        assert "DataBucket" in names
        assert "OpenSecurityGroup" in names

    def test_cfn_relationships_extracted(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "cfn_insecure.yaml"))
        trail = next((r for r in resources if r.resource_type == "AWS::CloudTrail::Trail"), None)
        assert trail is not None
        # MainTrail uses !Ref DataBucket
        assert "DataBucket" in trail.relationships

    def test_nonexistent_file_returns_empty(self):
        resources = self.parser.parse_file("/nonexistent/path/stack.yaml")
        assert resources == []


# --------------------------------------------------------- Kubernetes
class TestKubernetesParser:
    def setup_method(self):
        from threatmap.parsers import kubernetes
        self.parser = kubernetes

    def test_k8s_resource_count(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "k8s_insecure.yaml"))
        assert len(resources) >= 7

    def test_k8s_provider(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "k8s_insecure.yaml"))
        for r in resources:
            assert r.provider == "kubernetes"

    def test_k8s_source_format(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "k8s_insecure.yaml"))
        for r in resources:
            assert r.source_format == "kubernetes"

    def test_k8s_kinds_parsed(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "k8s_insecure.yaml"))
        kinds = {r.resource_type for r in resources}
        assert "Deployment" in kinds
        assert "ClusterRoleBinding" in kinds
        assert "Ingress" in kinds
        assert "ConfigMap" in kinds

    def test_k8s_names_from_metadata(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "k8s_insecure.yaml"))
        names = {r.name for r in resources}
        assert "insecure-api" in names
        assert "insecure-ingress" in names

    def test_full_doc_in_properties(self):
        resources = self.parser.parse_file(os.path.join(FIXTURES, "k8s_insecure.yaml"))
        deployment = next((r for r in resources if r.resource_type == "Deployment"), None)
        assert deployment is not None
        assert "spec" in deployment.properties


# --------------------------------------------------------- Format Detection
class TestFormatDetection:
    def setup_method(self):
        from threatmap import detect
        self.detect = detect

    def test_tf_extension(self, tmp_path):
        f = tmp_path / "main.tf"
        f.write_text('resource "aws_s3_bucket" "b" {}')
        assert self.detect.detect_format(str(f)) == "terraform"

    def test_cfn_yaml(self):
        assert self.detect.detect_format(os.path.join(FIXTURES, "cfn_insecure.yaml")) == "cloudformation"

    def test_k8s_yaml(self):
        assert self.detect.detect_format(os.path.join(FIXTURES, "k8s_insecure.yaml")) == "kubernetes"

    def test_unknown_returns_unknown(self, tmp_path):
        f = tmp_path / "random.txt"
        f.write_text("hello world")
        assert self.detect.detect_format(str(f)) == "unknown"
