terraform {
  required_version = "~> 1.14.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 7.45.0"
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

  app                                     = "example"
  project_id                              = "example"
  region                                  = "us-east4"
  service_name                            = "example"
  artifact_registry_repository_id         = "site"
  artifact_registry_description           = "Container images for example."
  bootstrap_image                         = "us-docker.pkg.dev/cloudrun/container/hello@sha256:9a0e9a5c7a19281e7617991d2fc61809de4973e6e75a10b2f07df3719ffda33c"
  bootstrap_runtime_service_account_email = "cloud-run-bootstrap@example.iam.gserviceaccount.com"
  runtime_service_account_email           = "cloud-run-runtime@example.iam.gserviceaccount.com"
  preview_runtime_service_account_email   = "cloud-run-preview@example.iam.gserviceaccount.com"
  preview_ingress                         = "INGRESS_TRAFFIC_ALL"
  prod_deploy_service_account_email       = "gha-prod-deploy@example.iam.gserviceaccount.com"
  prod_publisher_service_account_email    = "gha-prod-publish@example.iam.gserviceaccount.com"
  preview_deploy_service_account_email    = "gha-preview-deploy@example.iam.gserviceaccount.com"
  preview_operator_service_account_email  = "gha-preview-operator@example.iam.gserviceaccount.com"
  preview_publisher_service_account_email = "gha-preview-publish@example.iam.gserviceaccount.com"
  runtime_secret_ids                      = []
  runtime_secret_accessor_ids             = []
}
