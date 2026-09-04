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
  github_repository_id        = "123456789"
  active_workflow_sha         = "0123456789abcdef0123456789abcdef01234567"

  manage_automatic_default_service_account_grants_policy = false
}
