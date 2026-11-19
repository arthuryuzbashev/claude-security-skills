resource "google_storage_bucket_iam_member" "reader" {
  bucket = "example-test-bucket"
  role   = "roles/storage.objectViewer"
  member = "group:readers@example.test"
}

resource "google_compute_firewall" "https" {
  name          = "allow-https"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "azurerm_network_security_rule" "ssh" {
  name                        = "ssh-from-vpn"
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_address_prefix       = "198.51.100.0/24"
  destination_port_range      = "22"
  destination_address_prefix  = "*"
  priority                    = 100
  resource_group_name         = "rg"
  network_security_group_name = "nsg"
}

resource "azurerm_storage_account" "data" {
  name                            = "exampletestdata"
  resource_group_name             = "rg"
  location                        = "westeurope"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
}
