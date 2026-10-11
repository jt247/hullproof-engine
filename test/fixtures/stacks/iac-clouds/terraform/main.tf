provider "aws" {
  region = "eu-west-1"
}

provider "azurerm" {
  features {}
}

resource "google_storage_bucket" "logs" {
  name = "fixture-logs"
}

resource "cloudflare_record" "www" {
  name = "www"
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "foobarcloud_widget" "w" {
  size = 1
}
