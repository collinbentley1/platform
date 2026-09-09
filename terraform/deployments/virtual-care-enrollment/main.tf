variable "active_workflow_sha" {
  description = "Exact reviewed platform commit being enrolled. Keep GitHub Actions disabled until owner review and exact-WIF verification."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.active_workflow_sha))
    error_message = "active_workflow_sha must be an exact reviewed platform commit."
  }
}

provider "google" {
  project = "virtual-care-mcp"
  region  = "us-east4"
}

module "bootstrap" {
  source = "../../modules/bootstrap"

  app                         = "virtual-care-mcp"
  project_id                  = "virtual-care-mcp"
  region                      = "us-east4"
  state_bucket_name           = "virtual-care-mcp-tfstate"
  bootstrap_state_bucket_name = "virtual-care-mcp-tfstate-bootstrap"
  state_bucket_location       = "US-EAST4"
  github_owner                = "collinbentley1"
  github_repo                 = "virtual-care-mcp"
  github_repository_id        = "1362801465"
  active_workflow_sha         = var.active_workflow_sha
  federation_quarantined      = true

  manage_automatic_default_service_account_grants_policy = false
  manage_firestore_field_ttl                             = true
  required_services = [
    "artifactregistry.googleapis.com",
    "cloudasset.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "firestore.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "run.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
    "sts.googleapis.com",
  ]
  runtime_project_roles = ["roles/datastore.user"]
  runtime_description   = "Runtime identity for the virtual-care-mcp Cloud Run services."
}
