# Intentionally insecure Azure configuration — used for testing only

resource "azurerm_storage_account" "main_storage" {
  name                     = "insecurestorage001"
  resource_group_name      = "rg-test"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_blob_public_access    = true
  enable_https_traffic_only   = false
  min_tls_version             = "TLS1_0"
  # No network_rules
}

resource "azurerm_key_vault" "main_kv" {
  name                = "insecure-kv"
  location            = "westeurope"
  resource_group_name = "rg-test"
  sku_name            = "standard"
  tenant_id           = "00000000-0000-0000-0000-000000000000"

  purge_protection_enabled = false
  # No network_acls
}

resource "azurerm_network_security_group" "open_nsg" {
  name                = "open-nsg"
  location            = "westeurope"
  resource_group_name = "rg-test"

  security_rule {
    name                       = "allow-ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-rdp"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

resource "azurerm_role_assignment" "owner_sub" {
  scope                = "/subscriptions/00000000-0000-0000-0000-000000000000"
  role_definition_name = "Owner"
  principal_id         = "00000000-0000-0000-0000-000000000001"
}

resource "azurerm_linux_web_app" "api" {
  name                = "insecure-api"
  resource_group_name = "rg-test"
  location            = "westeurope"
  service_plan_id     = "plan-001"

  https_only = false
  # No identity block

  site_config {}
}

resource "azurerm_kubernetes_cluster" "main_aks" {
  name                = "insecure-aks"
  location            = "westeurope"
  resource_group_name = "rg-test"
  dns_prefix          = "insecure-aks"

  role_based_access_control_enabled = false
  # No api_server_authorized_ip_ranges

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_DS2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_container_registry" "main_acr" {
  name                = "insecureacr001"
  resource_group_name = "rg-test"
  location            = "westeurope"
  sku                 = "Standard"
  admin_enabled       = true
}

resource "azurerm_mssql_server" "main_sql" {
  name                = "insecure-sql-server"
  resource_group_name = "rg-test"
  location            = "westeurope"
  version             = "12.0"
  administrator_login = "sqladmin"
  administrator_login_password = "P@ssword123!"

  public_network_access_enabled = true
}

resource "azurerm_linux_virtual_machine" "jumpbox" {
  name                = "insecure-jumpbox"
  resource_group_name = "rg-test"
  location            = "westeurope"
  size                = "Standard_B2s"
  admin_username      = "azureuser"

  disable_password_authentication = false
  admin_password                  = "Insecure@123"

  network_interface_ids = []
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }
}

resource "azurerm_mssql_database" "main_db" {
  name      = "insecure-db"
  server_id = azurerm_mssql_server.main_sql.id

  transparent_data_encryption_enabled = false
}
