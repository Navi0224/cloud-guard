# DELIBERATELY INSECURE example - for testing cloud-guard only. Do not apply.
# Each block is annotated with the rule it should trigger.

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

# TF-S3-001 (public ACL, inline legacy style) + TF-S3-002 (no encryption config)
resource "aws_s3_bucket" "public_assets" {
  bucket = "example-public-assets"
  acl    = "public-read"
}

# TF-S3-002 (no encryption config)
resource "aws_s3_bucket" "uploads" {
  bucket = "example-user-uploads"
}

# TF-S3-001 (public ACL via the separate aws_s3_bucket_acl resource)
resource "aws_s3_bucket_acl" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  acl    = "public-read-write"
}

# TF-EBS-001 (unencrypted volume)
resource "aws_ebs_volume" "data" {
  availability_zone = "eu-central-1a"
  size              = 20
}
