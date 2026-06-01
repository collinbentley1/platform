variable "app" {
  description = "Short application label."
  type        = string
}

variable "project_id" {
  description = "Google Cloud project ID."
  type        = string
}

variable "region" {
  description = "Primary Google Cloud region."
  type        = string
}

variable "state_bucket_name" {
  description = "Globally unique Cloud Storage bucket for Terraform state."
  type        = string
}

variable "state_bucket_location" {
  description = "Cloud Storage location for Terraform state."
  type        = string
}

variable "github_owner" {
  description = "GitHub repository owner."
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name."
  type        = string
}

variable "github_owner_id" {
  description = "Immutable numeric GitHub owner ID."
  type        = string
}

variable "github_repository_id" {
  description = "Immutable numeric GitHub repository ID."
  type        = string
}

variable "required_services" {
  description = "Google APIs required by the application project."
  type        = set(string)
  default = [
    "artifactregistry.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "run.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
    "sts.googleapis.com",
  ]
}

variable "terraform_project_roles" {
  description = "Project roles granted to the Terraform service account."
  type        = set(string)
  default = [
    "roles/artifactregistry.admin",
    "roles/browser",
    "roles/run.admin",
    "roles/serviceusage.serviceUsageAdmin",
  ]
}

variable "deploy_project_roles" {
  description = "Project roles granted to deploy service accounts."
  type = map(object({
    role   = string
    target = string
  }))
  default = {
    prod_browser      = { role = "roles/browser", target = "prod" }
    prod_run_admin    = { role = "roles/run.admin", target = "prod" }
    preview_browser   = { role = "roles/browser", target = "preview" }
    preview_run_admin = { role = "roles/run.admin", target = "preview" }
  }
}

variable "runtime_display_name" {
  description = "Display name for the Cloud Run runtime service account."
  type        = string
  default     = "Cloud Run Runtime"
}

variable "terraform_service_account_description" {
  description = "Description for the Terraform service account."
  type        = string
  default     = "Runs production Terraform from GitHub Actions on main."
}

variable "prod_deploy_service_account_description" {
  description = "Description for the production deploy service account."
  type        = string
  default     = "Builds and deploys the production Cloud Run service from main."
}

variable "preview_deploy_service_account_description" {
  description = "Description for the preview deploy service account."
  type        = string
  default     = "Builds, deploys, and deletes pull request Cloud Run previews."
}

variable "runtime_description" {
  description = "Description for the Cloud Run runtime service account."
  type        = string
  default     = "Runtime identity for Cloud Run services."
}
