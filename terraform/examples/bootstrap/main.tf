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

module "bootstrap" {
  source = "../../modules/bootstrap"

  app                   = "example"
  project_id            = "example"
  region                = "us-east4"
  state_bucket_name     = "example-tfstate"
  state_bucket_location = "US-EAST4"
  github_owner          = "collinbentley1"
  github_repo           = "example"
  github_owner_id       = "16823277"
  github_repository_id  = "123456789"
}
