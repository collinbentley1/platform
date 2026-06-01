terraform {
  required_version = "~> 1.14.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 7.34.0"
    }
  }
}

provider "google" {
  project = "example"
  region  = "us-east4"
}

provider "google" {
  alias                           = "no_attribution"
  project                         = "example"
  region                          = "us-east4"
  add_terraform_attribution_label = false
}

module "site" {
  source = "../../modules/cloud-run-service"

  providers = {
    google                = google
    google.no_attribution = google.no_attribution
  }

  app                                  = "example"
  project_id                           = "example"
  region                               = "us-east4"
  service_name                         = "example"
  artifact_registry_repository_id      = "site"
  artifact_registry_description        = "Container images for example."
  runtime_service_account_email        = "cloud-run-runtime@example.iam.gserviceaccount.com"
  prod_deploy_service_account_email    = "gha-prod-deploy@example.iam.gserviceaccount.com"
  preview_deploy_service_account_email = "gha-preview-deploy@example.iam.gserviceaccount.com"
  custom_domains                       = ["example.com", "www.example.com"]
}
