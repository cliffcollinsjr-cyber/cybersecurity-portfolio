# [DEMO] AWS security baseline example — encryption, logging, network, IAM lean
# NOT a complete production landing zone. Review before any use.

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

# KMS for demo encryption
resource "aws_kms_key" "demo" {
  description             = "DEMO portfolio CMK — not production"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags = {
    Project = var.project
    Label   = "DEMO"
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

# VPC flow logs → S3 (demo)
resource "aws_vpc" "demo" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name  = "${var.project}-vpc"
    Label = "DEMO"
  }
}

resource "aws_flow_log" "demo" {
  vpc_id               = aws_vpc.demo.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.logs.arn
}

# Least-privilege example IAM policy document (attach carefully in real envs)
data "aws_iam_policy_document" "readonly_security_audit" {
  statement {
    sid       = "SecurityAuditRead"
    effect    = "Allow"
    actions   = ["securityhub:Get*", "securityhub:List*", "securityhub:Describe*", "cloudtrail:LookupEvents", "config:Describe*", "config:Get*"]
    resources = ["*"]
  }
}

output "demo_vpc_id" {
  value = aws_vpc.demo.id
}

output "demo_log_bucket" {
  value = aws_s3_bucket.logs.bucket
}
