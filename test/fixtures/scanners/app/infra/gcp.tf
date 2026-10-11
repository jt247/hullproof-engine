# Synthetic fixture. Wrong on purpose.
resource "google_storage_bucket" "files" {
  name     = "hullproof-fixture-files"
  location = "EU"
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.files.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_sql_database_instance" "db" {
  name             = "db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "any"
        value = "0.0.0.0/0"
      }
    }
  }
}

resource "google_project_iam_member" "editor" {
  project = "fixture"
  role    = "roles/editor"
  member  = "serviceAccount:app@fixture.iam.gserviceaccount.com"
}

resource "google_compute_firewall" "ssh" {
  name    = "ssh"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
}
