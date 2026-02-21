# Example: Azure infrastructure with a mix of secure and insecure config

resource "azurerm_storage_account" "app_storage" {
  name                     = "myappstorage001"
  resource_group_name      = "rg-app"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "GRS"

  allow_blob_public_access  = false
  enable_https_traffic_only = true
  min_tls_version           = "TLS1_2"

  network_rules {
    default_action             = "Deny"
    ip_rules                   = ["203.0.113.0/24"]
    virtual_network_subnet_ids = []
  }
}

resource "azurerm_key_vault" "app_kv" {
  name                = "app-keyvault"
  location            = "westeurope"
  resource_group_name = "rg-app"
  sku_name            = "standard"
  tenant_id           = "00000000-0000-0000-0000-000000000000"

  purge_protection_enabled = true   # good

  # flagged: no network_acls block
}

resource "azurerm_network_security_group" "app_nsg" {
  name                = "app-nsg"
  location            = "westeurope"
  resource_group_name = "rg-app"

  security_rule {
    name                       = "allow-https"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
  }
}

resource "azurerm_role_assignment" "app_contributor" {
  scope                = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app"
  role_definition_name = "Contributor"   # flagged: Contributor is a privileged role
  principal_id         = "00000000-0000-0000-0000-000000000002"
}
