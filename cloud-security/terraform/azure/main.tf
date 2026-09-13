# [DEMO] Azure security baseline snippets
# Remote state / locking / apply gates: see iac-cicd-security/terraform-repo-hardening.md
# CI: terraform fmt -check + init -backend=false + validate (no cloud credentials).

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "prefix" {
  type    = string
  default = "cyberdemo"
}

resource "azurerm_resource_group" "demo" {
  name     = "${var.prefix}-rg"
  location = var.location
  tags     = { Label = "DEMO" }
}

resource "azurerm_log_analytics_workspace" "demo" {
  name                = "${var.prefix}-law"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
}

resource "azurerm_storage_account" "demo" {
  # checkov:skip=CKV_AZURE_33:Queue logging is on azurerm_storage_account_queue_properties (azurerm 5.x)
  name                       = "${var.prefix}sademo01"
  resource_group_name        = azurerm_resource_group.demo.name
  location                   = azurerm_resource_group.demo.location
  account_tier               = "Standard"
  account_replication_type   = "GRS"
  min_tls_version            = "TLS1_2"
  https_traffic_only_enabled = true
  # Kept for Checkov CKV_AZURE_59; azurerm 5.x prefers public_network_access (v6 removal).
  public_network_access_enabled     = false
  allow_nested_items_to_be_public   = false
  infrastructure_encryption_enabled = true
  # Explicit so Checkov graph check CKV2_AZURE_41 sees SAS policy + key auth together.
  # Shared-key disable (CKV2_AZURE_40) is waived in .checkov.yml — needs Entra data-plane.
  shared_access_key_enabled = true

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }

  sas_policy {
    expiration_period = "90.00:00:00"
  }

  tags = { Label = "DEMO" }
}

# azurerm 4+/5.x moved queue logging off the storage account resource.
resource "azurerm_storage_account_queue_properties" "demo" {
  storage_account_id = azurerm_storage_account.demo.id
  logging {
    delete                = true
    read                  = true
    write                 = true
    version               = "1.0"
    retention_policy_days = 10
  }
}

resource "azurerm_network_security_group" "demo" {
  name                = "${var.prefix}-nsg"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name

  security_rule {
    name                       = "deny-inbound-internet"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

output "resource_group" {
  value = azurerm_resource_group.demo.name
}
