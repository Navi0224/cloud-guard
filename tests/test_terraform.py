"""Terraform rules: one insecure and one fixed snippet per rule, plus the shipped examples."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloud_guard.terraform import rules
from cloud_guard.terraform.parser import parse_directory
from cloud_guard.terraform.scanner import scan_terraform
from tests.conftest import ids

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "terraform"

# A compliant CloudTrail, appended to snippets so TF-CT-001 doesn't add noise.
GOOD_TRAIL = """
resource "aws_cloudtrail" "t" {
  name                       = "t"
  s3_bucket_name             = "logs"
  is_multi_region_trail      = true
  enable_log_file_validation = true
}
"""


def scan_snippet(tmp_path: Path, hcl: str, with_trail: bool = True):
    (tmp_path / "main.tf").write_text(hcl + (GOOD_TRAIL if with_trail else ""), encoding="utf-8")
    return scan_terraform(tmp_path)


# ----------------------------------------------------------------- TF-S3-001 public ACL


@pytest.mark.parametrize("hcl", [
    'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl = "public-read"\n}',
    'resource "aws_s3_bucket_acl" "a" {\n  bucket = "x"\n  acl = "public-read-write"\n}',
    'resource "aws_s3_bucket_acl" "a" {\n  bucket = "x"\n  acl = "authenticated-read"\n}',
])
def test_public_acl_flagged(tmp_path, hcl):
    assert "TF-S3-001" in ids(scan_snippet(tmp_path, hcl).findings)


def test_private_acl_passes(tmp_path):
    hcl = 'resource "aws_s3_bucket_acl" "a" {\n  bucket = "x"\n  acl = "private"\n}'
    assert scan_snippet(tmp_path, hcl).findings == []


# ----------------------------------------------------------------- TF-S3-002 encryption


def test_bucket_without_encryption_flagged(tmp_path):
    hcl = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}'
    assert ids(scan_snippet(tmp_path, hcl).findings) == ["TF-S3-002"]


def test_bucket_with_separate_encryption_resource_passes(tmp_path):
    hcl = '''
resource "aws_s3_bucket" "b" { bucket = "x" }
resource "aws_s3_bucket_server_side_encryption_configuration" "e" {
  bucket = aws_s3_bucket.b.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}'''
    assert scan_snippet(tmp_path, hcl).findings == []


def test_bucket_with_legacy_inline_encryption_passes(tmp_path):
    hcl = '''
resource "aws_s3_bucket" "b" {
  bucket = "x"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
    }
  }
}'''
    assert scan_snippet(tmp_path, hcl).findings == []


def test_encryption_for_other_bucket_does_not_count(tmp_path):
    hcl = '''
resource "aws_s3_bucket" "a" { bucket = "a" }
resource "aws_s3_bucket" "b" { bucket = "b" }
resource "aws_s3_bucket_server_side_encryption_configuration" "e" {
  bucket = aws_s3_bucket.a.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}'''
    findings = scan_snippet(tmp_path, hcl).findings
    assert [f.resource for f in findings] == ["main.tf:aws_s3_bucket.b"]


# ----------------------------------------------------------------- TF-EBS-001


def test_unencrypted_ebs_flagged(tmp_path):
    hcl = 'resource "aws_ebs_volume" "v" {\n  availability_zone = "a"\n  size = 1\n}'
    assert ids(scan_snippet(tmp_path, hcl).findings) == ["TF-EBS-001"]


def test_encrypted_ebs_passes(tmp_path):
    hcl = 'resource "aws_ebs_volume" "v" {\n  availability_zone = "a"\n  size = 1\n  encrypted = true\n}'
    assert scan_snippet(tmp_path, hcl).findings == []


# ----------------------------------------------------------------- TF-SG-001


@pytest.mark.parametrize("hcl,count", [
    ('resource "aws_security_group" "s" {\n ingress {\n from_port = 22\n to_port = 22\n protocol = "tcp"\n'
     ' cidr_blocks = ["0.0.0.0/0"]\n }\n}', 1),
    ('resource "aws_security_group_rule" "r" {\n type = "ingress"\n from_port = 0\n to_port = 0\n'
     ' protocol = "-1"\n security_group_id = "sg-1"\n cidr_blocks = ["0.0.0.0/0"]\n}', 2),
    ('resource "aws_vpc_security_group_ingress_rule" "r" {\n security_group_id = "sg-1"\n'
     ' cidr_ipv6 = "::/0"\n from_port = 3389\n to_port = 3389\n ip_protocol = "tcp"\n}', 1),
])
def test_open_admin_ports_flagged(tmp_path, hcl, count):
    findings = scan_snippet(tmp_path, hcl).findings
    assert ids(findings) == ["TF-SG-001"] * count


@pytest.mark.parametrize("hcl", [
    # SSH from a private range
    'resource "aws_security_group" "s" {\n ingress {\n from_port = 22\n to_port = 22\n protocol = "tcp"\n'
    ' cidr_blocks = ["10.0.0.0/8"]\n }\n}',
    # HTTPS from anywhere
    'resource "aws_security_group" "s" {\n ingress {\n from_port = 443\n to_port = 443\n protocol = "tcp"\n'
    ' cidr_blocks = ["0.0.0.0/0"]\n }\n}',
    # egress rules are not ingress
    'resource "aws_security_group_rule" "r" {\n type = "egress"\n from_port = 22\n to_port = 22\n'
    ' protocol = "tcp"\n security_group_id = "sg-1"\n cidr_blocks = ["0.0.0.0/0"]\n}',
])
def test_safe_security_rules_pass(tmp_path, hcl):
    assert scan_snippet(tmp_path, hcl).findings == []


# ----------------------------------------------------------------- TF-IAM-001


ADMIN_JSONENCODE = '''
resource "aws_iam_policy" "p" {
  name = "p"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["*"], Resource = "*" }]
  })
}'''

ADMIN_HEREDOC = '''
resource "aws_iam_role_policy" "p" {
  name = "p"
  role = "r"
  policy = <<EOF
{"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "*:*", "Resource": "*"}}
EOF
}'''

ADMIN_DATA_DOC = '''
data "aws_iam_policy_document" "d" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}'''

# References inside jsonencode can't be turned into JSON, so the regex fallback is used.
ADMIN_JSONENCODE_WITH_REF = '''
resource "aws_iam_policy" "p" {
  name = "p"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "s3:GetObject", Resource = aws_s3_bucket.b.arn },
      { Effect = "Allow", Action = "*", Resource = "*" }
    ]
  })
}'''


@pytest.mark.parametrize("hcl", [ADMIN_JSONENCODE, ADMIN_HEREDOC, ADMIN_DATA_DOC, ADMIN_JSONENCODE_WITH_REF])
def test_wildcard_iam_flagged(tmp_path, hcl):
    assert ids(scan_snippet(tmp_path, hcl).findings) == ["TF-IAM-001"]


@pytest.mark.parametrize("hcl", [
    ADMIN_JSONENCODE.replace('Resource = "*"', 'Resource = "arn:aws:s3:::x/*"'),
    ADMIN_DATA_DOC.replace("statement {", 'statement {\n    effect = "Deny"'),
    'resource "aws_iam_role_policy" "p" {\n  name = "p"\n  role = "r"\n  policy = data.aws_iam_policy_document.d.json\n}',
])
def test_scoped_iam_passes(tmp_path, hcl):
    assert scan_snippet(tmp_path, hcl).findings == []


def test_jsonencode_is_parsed_as_json_not_regex():
    text = '${jsonencode({Version = "2012-10-17", Statement = [{Effect = "Allow", Action = "*", Resource = "*"}]})}'
    assert rules.policy_text_is_admin(text) is True
    deny = text.replace('"Allow"', '"Deny"')
    assert rules.policy_text_is_admin(deny) is False  # only the JSON path understands Effect


# ----------------------------------------------------------------- TF-CT-00x


def test_missing_cloudtrail_flagged(tmp_path):
    hcl = 'resource "aws_ebs_volume" "v" {\n  availability_zone = "a"\n  size = 1\n  encrypted = true\n}'
    assert ids(scan_snippet(tmp_path, hcl, with_trail=False).findings) == ["TF-CT-001"]


def test_weak_cloudtrail_flagged(tmp_path):
    hcl = 'resource "aws_cloudtrail" "t" {\n  name = "t"\n  s3_bucket_name = "logs"\n}'
    assert ids(scan_snippet(tmp_path, hcl, with_trail=False).findings) == ["TF-CT-002", "TF-CT-003"]


def test_good_cloudtrail_passes(tmp_path):
    assert scan_snippet(tmp_path, "").findings == []


# ----------------------------------------------------------------- examples and robustness


def test_insecure_example_triggers_every_rule():
    result = scan_terraform(EXAMPLES / "insecure")
    assert set(ids(result.findings)) == {
        "TF-S3-001", "TF-S3-002", "TF-EBS-001", "TF-SG-001", "TF-IAM-001", "TF-CT-001",
    }
    assert result.skipped == []


def test_secure_example_is_clean():
    result = scan_terraform(EXAMPLES / "secure")
    assert result.findings == []
    assert result.skipped == []


def test_parse_error_in_one_file_does_not_stop_scan(tmp_path):
    (tmp_path / "broken.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = \n', encoding="utf-8")
    (tmp_path / "ok.tf").write_text('resource "aws_ebs_volume" "v" {\n  size = 1\n}' + GOOD_TRAIL, encoding="utf-8")
    result = scan_terraform(tmp_path)
    assert ids(result.findings) == ["TF-EBS-001"]
    assert [s.check_id for s in result.skipped] == ["parse:broken.tf"]


def test_terraform_cache_dir_is_ignored(tmp_path):
    cache = tmp_path / ".terraform" / "modules"
    cache.mkdir(parents=True)
    (cache / "vendor.tf").write_text('resource "aws_ebs_volume" "v" {\n  size = 1\n}', encoding="utf-8")
    (tmp_path / "main.tf").write_text(GOOD_TRAIL, encoding="utf-8")
    assert scan_terraform(tmp_path).findings == []


def test_empty_directory_reports_skip(tmp_path):
    result = scan_terraform(tmp_path)
    assert result.findings == [] and result.skipped[0].reason == "no .tf files found"


def test_missing_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan_terraform(tmp_path / "nope")


def test_parser_returns_relative_paths(tmp_path):
    sub = tmp_path / "modules" / "net"
    sub.mkdir(parents=True)
    (sub / "sg.tf").write_text('resource "aws_security_group" "s" {}', encoding="utf-8")
    blocks, errors = parse_directory(tmp_path)
    assert errors == []
    assert blocks[0].location == "modules/net/sg.tf:aws_security_group.s"
