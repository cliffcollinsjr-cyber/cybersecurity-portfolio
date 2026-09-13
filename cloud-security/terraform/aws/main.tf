# [DEMO] AWS security baseline example — encryption, logging, network, IAM lean
# NOT a complete production landing zone. Review before any use.
# Remote state / locking / apply gates: see iac-cicd-security/terraform-repo-hardening.md
# CI: terraform fmt -check + init -backend=false + validate (no cloud credentials).

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "project" {
  type    = string
  default = "cyber-portfolio-demo"
}

# Placeholder account id used only to render a KMS key policy for validate/plan.
# Replace with data.aws_caller_identity in a real account you own.
variable "aws_account_id" {
  type        = string
  description = "[DEMO] AWS account id placeholder for KMS key policy"
  default     = "123456789012"
}

# AWS-recommended CMK policy: account root must be able to administer the key.
# checkov:skip=CKV_AWS_109:Account-root kms:* on this CMK is the AWS default admin pattern
# checkov:skip=CKV_AWS_111:Account-root kms:* on this CMK is the AWS default admin pattern
data "aws_iam_policy_document" "kms_demo" {
  # checkov:skip=CKV_AWS_109:Account-root kms:* on this CMK is the AWS default admin pattern
  # checkov:skip=CKV_AWS_111:Account-root kms:* on this CMK is the AWS default admin pattern
  statement {
    sid    = "EnableAccountRoot"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}

# KMS for demo encryption
resource "aws_kms_key" "demo" {
  description             = "DEMO portfolio CMK — not production"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_demo.json
  tags = {
    Project = var.project
    Label   = "DEMO"
  }
}

resource "aws_kms_alias" "demo" {
  name          = "alias/${var.project}-demo"
  target_key_id = aws_kms_key.demo.key_id
}

# Access-log target for the primary log bucket (CKV_AWS_18).
# checkov:skip=CKV_AWS_18:Access-log target cannot log to itself in this DEMO
resource "aws_s3_bucket" "access_logs" {
  bucket_prefix = "${var.project}-s3-access-"
  tags = {
    Project = var.project
    Label   = "DEMO"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.demo.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "expire-access-logs"
    status = "Enabled"
    filter {
      prefix = ""
    }
    expiration {
      days = 90
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket" "logs" {
  bucket_prefix = "${var.project}-logs-"
  tags = {
    Project = var.project
    Label   = "DEMO"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.demo.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "logs" {
  bucket        = aws_s3_bucket.logs.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3-access/"
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire-demo-logs"
    status = "Enabled"
    filter {
      prefix = ""
    }
    expiration {
      days = 90
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# VPC flow logs → S3 (demo)
resource "aws_vpc" "demo" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name  = "${var.project}-vpc"
    Label = "DEMO"
  }
}

# Lock the default SG (no ingress/egress rules = deny all).
resource "aws_default_security_group" "demo" {
  vpc_id = aws_vpc.demo.id
  tags = {
    Name  = "${var.project}-default-sg-locked"
    Label = "DEMO"
  }
}

resource "aws_flow_log" "demo" {
  vpc_id               = aws_vpc.demo.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.logs.arn
}

# Least-privilege example IAM policy document (attach carefully in real envs).
# SecurityHub / CloudTrail / Config read APIs are not resource-ARN restrictable.
# checkov:skip=CKV_AWS_356:Read-only security-audit APIs require Resource=*
data "aws_iam_policy_document" "readonly_security_audit" {
  statement {
    sid    = "SecurityAuditRead"
    effect = "Allow"
    actions = [
      "securityhub:Get*",
      "securityhub:List*",
      "securityhub:Describe*",
      "cloudtrail:LookupEvents",
      "config:Describe*",
      "config:Get*",
    ]
    resources = ["*"]
  }
}

output "demo_vpc_id" {
  value = aws_vpc.demo.id
}

output "demo_log_bucket" {
  value = aws_s3_bucket.logs.bucket
}
