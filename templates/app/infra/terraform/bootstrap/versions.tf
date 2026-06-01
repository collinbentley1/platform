terraform {
  required_version = "~> 1.14.0"

  backend "gcs" {
    bucket = "__STATE_BUCKET__"
    prefix = "__APP_NAME__/bootstrap"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 7.34.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
