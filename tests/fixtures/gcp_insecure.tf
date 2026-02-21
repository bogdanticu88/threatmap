# Intentionally insecure GCP configuration — used for testing only

resource "google_storage_bucket" "data_bucket" {
  name     = "insecure-data-bucket"
  location = "EU"

  uniform_bucket_level_access = false
  # No public_access_prevention
  # No logging
}

resource "google_compute_firewall" "open_firewall" {
  name    = "open-firewall"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_instance" "web_server" {
  name         = "insecure-web-server"
  machine_type = "e2-medium"
  zone         = "europe-west1-b"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
    access_config {}
  }

  metadata = {
    "block-project-ssh-keys" = "false"
  }

  # No shielded_instance_config
}

resource "google_sql_database_instance" "main_db" {
  name             = "insecure-mysql"
  database_version = "MYSQL_8_0"
  region           = "europe-west1"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true
    }

    backup_configuration {
      enabled = false
    }
  }
}

resource "google_container_cluster" "main_cluster" {
  name     = "insecure-cluster"
  location = "europe-west1"

  initial_node_count = 1

  # No master_authorized_networks_config
  # No network_policy
  # No workload_identity_config
}

resource "google_project_iam_binding" "owner_binding" {
  project = "my-project"
  role    = "roles/owner"

  members = [
    "user:admin@example.com",
  ]
}

resource "google_kms_crypto_key" "main_key" {
  name     = "main-key"
  key_ring = "projects/my-project/locations/global/keyRings/main-keyring"
  # No rotation_period
}

resource "google_compute_project_metadata" "default" {
  metadata = {
    "enable-oslogin" = "FALSE"
  }
}
