# [DEMO] GCP security baseline snippets
# Remote state / locking / apply gates: see iac-cicd-security/terraform-repo-hardening.md
# CI: terraform fmt -check + init -backend=false + validate (no cloud credentials).

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "GCP project id you own (lab)"
  default     = "demo-cyber-portfolio"
}

variable "region" {
  type    = string
  default = "us-central1"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Access-log sink for the primary security-logs bucket (CKV_GCP_62).
# Cannot self-log (CKV_GCP_63) and cannot log elsewhere without a third bucket.
resource "google_storage_bucket" "access_logs" {
  # checkov:skip=CKV_GCP_62:Log-sink target cannot self-log (CKV_GCP_63); primary bucket is logged
  name                        = "${var.project_id}-gcs-access-logs-demo"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  versioning {
    enabled = true
  }
  labels = {
    label = "demo"
  }
}

resource "google_storage_bucket" "logs" {
  name                        = "${var.project_id}-security-logs-demo"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  versioning {
    enabled = true
  }
  logging {
    log_bucket        = google_storage_bucket.access_logs.name
    log_object_prefix = "gcs-access/"
  }
  labels = {
    label = "demo"
  }
  # force_destroy intentionally omitted / false mindset for real data
  # CMEK omitted in DEMO (no lab KMS key). Production: set default_kms_key_name.
}

resource "google_compute_firewall" "deny_all_ingress" {
  name      = "demo-deny-all-ingress"
  network   = "default"
  direction = "INGRESS"
  priority  = 65534
  deny {
    protocol = "all"
  }
  source_ranges = ["0.0.0.0/0"]
  description   = "DEMO: explicit deny high priority — ensure allow rules exist above for needed traffic"
}

# Example least-privilege custom role sketch via IAM member binding is org-specific;
# prefer predefined roles like roles/viewer for audit identities in labs.
