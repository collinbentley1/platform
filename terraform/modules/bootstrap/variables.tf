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
  description = "Globally unique Cloud Storage bucket for routine production Terraform state."
  type        = string
}

variable "bootstrap_state_bucket_name" {
  description = "Globally unique, separately protected bucket for privileged bootstrap Terraform state."
  type        = string

  validation {
    condition     = var.bootstrap_state_bucket_name != var.state_bucket_name
    error_message = "bootstrap_state_bucket_name must be distinct from the routine production state bucket."
  }
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

variable "github_repository_id" {
  description = "Immutable numeric GitHub repository ID."
  type        = string

  validation {
    condition     = can(regex("^[1-9][0-9]*$", var.github_repository_id))
    error_message = "github_repository_id must be a positive decimal ID."
  }
}

variable "active_workflow_sha" {
  description = "Exact reviewed platform commit whose reusable workflows exchange GitHub OIDC tokens for every cloud workflow authority."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.active_workflow_sha))
    error_message = "active_workflow_sha must be one full lowercase commit SHA."
  }
}

variable "transition_workflow_sha" {
  description = "Optional immediately previous reviewed platform commit that only transition-eligible workflow authorities may keep exchanging while consumers repin. Null at steady state."
  type        = string
  default     = null

  validation {
    condition     = var.transition_workflow_sha == null || can(regex("^[0-9a-f]{40}$", var.transition_workflow_sha))
    error_message = "transition_workflow_sha must be null or one full lowercase commit SHA."
  }

  validation {
    condition     = var.transition_workflow_sha != var.active_workflow_sha
    error_message = "transition_workflow_sha must differ from active_workflow_sha."
  }
}

variable "manage_automatic_default_service_account_grants_policy" {
  description = "Explicitly manage iam.automaticIamGrantsForDefaultServiceAccounts only when the project has an organization parent and the protected bootstrap identity has organization-level policy authority. Standalone projects must set false while the authoritative empty Editor binding still removes every direct Editor member."
  type        = bool
}

variable "federation_quarantined" {
  description = "Disable the GitHub Actions workload identity pool for the duration of a protected apply. A disabled pool cannot be used to exchange tokens OR to use already-issued tokens against resources, so it removes consumer federation from the privileged window outright rather than arguing about token lifetimes. The protected bridge sets this true for the apply it performs and restores the reviewed state afterwards."
  type        = bool
  default     = false
}

variable "required_services" {
  description = "Google APIs required by the application project."
  type        = set(string)
  default = [
    "artifactregistry.googleapis.com",
    "cloudasset.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "run.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
    "sts.googleapis.com",
  ]
}

variable "manage_firestore_field_ttl" {
  description = "Whether the protected apply identity may patch Firestore field TTL policies. Off by default: only an application that declares google_firestore_field needs it, and it is the difference between reading index metadata and rewriting it."
  type        = bool
  default     = false
}

variable "runtime_project_roles" {
  description = "Intentional project-level data roles granted to the production runtime service account by the protected bootstrap pipeline."
  type        = set(string)
  default     = []
}

variable "runtime_display_name" {
  description = "Display name for the Cloud Run runtime service account."
  type        = string
  default     = "Cloud Run Runtime"
}

variable "preview_runtime_display_name" {
  description = "Display name for the no-data preview Cloud Run runtime service account."
  type        = string
  default     = "Cloud Run Preview Runtime"
}

variable "terraform_service_account_description" {
  description = "Description for the Terraform service account."
  type        = string
  default     = "Runs a metadata-only production Terraform convergence plan from GitHub Actions on main."
}

variable "prod_deploy_service_account_description" {
  description = "Description for the production deploy service account."
  type        = string
  default     = "Updates only the pre-created production Cloud Run service, reads its exact image repository, and may add versions only to platform-declared exact secrets from protected main."
}

variable "prod_publisher_service_account_description" {
  description = "Description for the production Artifact Registry publisher service account."
  type        = string
  default     = "Copies verified production images into only the application production Artifact Registry repository."
}

variable "preview_deploy_service_account_description" {
  description = "Description for the preview deploy service account."
  type        = string
  default     = "Deploys only to the pre-created shared preview Cloud Run service and reads its exact image repository."
}

variable "preview_operator_service_account_description" {
  description = "Description for the preview traffic operator service account."
  type        = string
  default     = "Retired preview traffic identity retained only for an explicitly declared workflow-SHA transition; receives no steady-state operational grants."
}

variable "preview_publisher_service_account_description" {
  description = "Description for the preview Artifact Registry publisher service account."
  type        = string
  default     = "Copies verified pull request images into only the application preview Artifact Registry repository."
}

variable "runtime_description" {
  description = "Description for the Cloud Run runtime service account."
  type        = string
  default     = "Runtime identity for Cloud Run services."
}

variable "preview_runtime_description" {
  description = "Description for the no-data preview Cloud Run runtime service account."
  type        = string
  default     = "Runtime identity for untrusted pull request previews; intentionally has no project data roles."
}
