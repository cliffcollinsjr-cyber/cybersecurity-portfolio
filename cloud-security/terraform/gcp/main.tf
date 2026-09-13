# [DEMO] GCP security baseline snippets
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

resource "google_storage_bucket" "logs" {
  name                        = "${var.project_id}-security-logs-demo"
  location                    = var.region
  uniform_bucket_level_access = true
  versioning {
    enabled = true
  }
  encryption {
    default_kms_key_name = null # set to CMEK in real deployments
  }
  labels = {
    label = "demo"
  }
  # force_destroy intentionally omitted / false mindset for real data
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
