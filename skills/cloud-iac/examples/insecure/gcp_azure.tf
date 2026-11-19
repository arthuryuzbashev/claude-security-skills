# Example only: weak GCP and Azure settings
resource "google_storage_bucket_iam_member" "public" {
  bucket = "example-test-bucket"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_compute_firewall" "ssh" {
  name          = "allow-ssh"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22", "8080-8090"]
  }
}

resource "azurerm_network_security_rule" "rdp" {
  name                        = "rdp"
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_address_prefix       = "Internet"
  destination_port_range      = "3389"
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
  min_tls_version                 = "TLS1_0"
  allow_nested_items_to_be_public = true
}
