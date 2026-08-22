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

module "bootstrap" {
  source = "../../modules/bootstrap"

  app                         = "example"
  project_id                  = "example"
  region                      = "us-east4"
  state_bucket_name           = "example-tfstate"
  bootstrap_state_bucket_name = "example-bootstrap-tfstate"
  state_bucket_location       = "US-EAST4"
  github_owner                = "collinbentley1"
  github_repo                 = "example"
  github_owner_id             = "16823277"
  github_repository_id        = "123456789"
  trusted_platform_workflow_shas = [
    "0123456789abcdef0123456789abcdef01234567",
  ]
  preview_operations_active_workflow_shas = [
    "0123456789abcdef0123456789abcdef01234567",
  ]
  preview_operator_transition_workflow_shas              = []
  legacy_compatibility_mode                              = false
  manage_automatic_default_service_account_grants_policy = false
}
