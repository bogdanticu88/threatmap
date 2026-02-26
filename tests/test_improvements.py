import os
import subprocess
import sys
from threatmap.reporters import markdown
from threatmap.models.resource import Resource
from threatmap.models.threat import Threat, Severity, StrideCategory

def test_module_execution():
    """Test that 'python -m threatmap' works."""
    result = subprocess.run(
        [sys.executable, "-m", "threatmap", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "threatmap" in result.stdout

def test_ascii_mode_markdown():
    """Test that ASCII mode in Markdown reporter works."""
    resources = [
        Resource(
            name="bucket",
            resource_type="aws_s3_bucket",
            provider="aws",
            source_format="terraform",
            source_file="main.tf",
            properties={}
        )
    ]
    threats = [
        Threat(
            threat_id="T1",
            stride_category=StrideCategory.TAMPERING,
            severity=Severity.HIGH,
            resource_name="bucket",
            resource_type="aws_s3_bucket",
            description="Public bucket",
            mitigation="Private bucket"
        )
    ]
    
    # Emoji mode (default)
    report_emoji = markdown.build_report(resources, threats, "test.tf", ascii_mode=False)
    assert "🟠 HIGH" in report_emoji
    
    # ASCII mode
    report_ascii = markdown.build_report(resources, threats, "test.tf", ascii_mode=True)
    assert "[HIGH]" in report_ascii
    assert "🟠" not in report_ascii

def test_markdown_encoding_and_newline(tmp_path):
    """Test that Markdown report is written with UTF-8 and LF."""
    from threatmap.cli import scan
    from click.testing import CliRunner
    
    runner = CliRunner()
    # Create a dummy IaC file
    iac_file = tmp_path / "main.tf"
    iac_file.write_text('resource "aws_s3_bucket" "b" {}')
    
    output_file = tmp_path / "report.md"
    
    result = runner.invoke(scan, [str(iac_file), "--output", str(output_file)])
    assert result.exit_code == 0
    
    # Read file in binary to check for LF
    with open(output_file, "rb") as f:
        content = f.read()
        # Verify it has Unix newlines (\n) and not Windows (\r\n)
        assert b"\r\n" not in content
        assert b"\n" in content
        
    # Should be decodable as UTF-8
    content.decode("utf-8")
