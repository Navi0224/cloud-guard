# The "fixed" counterpart of ../insecure. cloud-guard should report 0 findings here.
# (Illustrative only - review before applying to a real account.)

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-central-1"
}

resource "aws_kms_key" "data" {
  description         = "Key for S3 and EBS encryption"
  enable_key_rotation = true
}

# ---------------------------------------------------------------- S3

resource "aws_s3_bucket" "uploads" {
  bucket = "example-user-uploads"
}

# ACLs disabled entirely: the bucket owner owns every object.
resource "aws_s3_bucket_ownership_controls" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}

# ---------------------------------------------------------------- EBS

resource "aws_ebs_encryption_by_default" "on" {
  enabled = true
}

resource "aws_ebs_volume" "data" {
  availability_zone = "eu-central-1a"
  size              = 20
  encrypted         = true
  kms_key_id        = aws_kms_key.data.arn
}

# ---------------------------------------------------------------- CloudTrail

resource "aws_s3_bucket" "trail_logs" {
  bucket = "example-cloudtrail-logs"
}

resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket                  = aws_s3_bucket.trail_logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_cloudtrail" "main" {
  name                       = "org-audit-trail"
  s3_bucket_name             = aws_s3_bucket.trail_logs.id
  is_multi_region_trail      = true
  enable_log_file_validation = true
  include_global_service_events = true
}
