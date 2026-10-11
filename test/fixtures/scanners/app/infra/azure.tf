# Synthetic fixture. Wrong on purpose.
resource "azurerm_storage_account" "files" {
  name                            = "hullprooffixture"
  resource_group_name             = "rg"
  location                        = "westeurope"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  min_tls_version                 = "TLS1_0"
}

resource "azurerm_storage_container" "files" {
  name                  = "files"
  storage_account_name  = azurerm_storage_account.files.name
  container_access_type = "blob"
}

resource "azurerm_network_security_rule" "rdp" {
  name                        = "rdp"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg"
  network_security_group_name = "nsg"
}

resource "azurerm_role_definition" "all" {
  name  = "all"
  scope = "/subscriptions/00000000-0000-0000-0000-000000000000"
  permissions {
    actions = ["*"]
  }
  assignable_scopes = ["/subscriptions/00000000-0000-0000-0000-000000000000"]
}
