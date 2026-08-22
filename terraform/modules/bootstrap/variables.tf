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

variable "github_owner_id" {
  description = "Immutable numeric GitHub owner ID."
  type        = string

  validation {
    condition     = can(regex("^[1-9][0-9]*$", var.github_owner_id))
    error_message = "github_owner_id must be a positive decimal ID."
  }
}

variable "github_repository_id" {
  description = "Immutable numeric GitHub repository ID."
  type        = string

  validation {
    condition     = can(regex("^[1-9][0-9]*$", var.github_repository_id))
    error_message = "github_repository_id must be a positive decimal ID."
  }
}

variable "trusted_platform_workflow_shas" {
  description = "Reviewed platform commits whose reusable workflows may exchange GitHub OIDC tokens."
  type        = set(string)

  validation {
    condition = (
      length(var.trusted_platform_workflow_shas) > 0 &&
      alltrue([for sha in var.trusted_platform_workflow_shas : can(regex("^[0-9a-f]{40}$", sha))])
    )
    error_message = "trusted_platform_workflow_shas must contain one or more full lowercase commit SHAs."
  }
}

variable "preview_operations_active_workflow_shas" {
  description = "Nonempty reviewed platform commit set whose preview-operations workflows exchange through the preview deploy service account. Must be disjoint from the transition set and together exactly partition trusted_platform_workflow_shas."
  type        = set(string)

  validation {
    condition = (
      length(var.preview_operations_active_workflow_shas) > 0 &&
      alltrue([for sha in var.preview_operations_active_workflow_shas : can(regex("^[0-9a-f]{40}$", sha))]) &&
      length(setintersection(var.preview_operations_active_workflow_shas, var.preview_operator_transition_workflow_shas)) == 0 &&
      setunion(var.preview_operations_active_workflow_shas, var.preview_operator_transition_workflow_shas) == var.trusted_platform_workflow_shas
    )
    error_message = "preview_operations_active_workflow_shas must be nonempty, contain full lowercase commit SHAs, be disjoint from the transition set, and together exactly partition trusted_platform_workflow_shas."
  }
}

variable "preview_operator_transition_workflow_shas" {
  description = "Immediately previous reviewed platform commit set temporarily allowed to exchange preview-operations tokens through the retired preview operator identity. Empty at steady state."
  type        = set(string)
  default     = []

  validation {
    condition = (
      alltrue([for sha in var.preview_operator_transition_workflow_shas : can(regex("^[0-9a-f]{40}$", sha))]) &&
      length(setsubtract(var.preview_operator_transition_workflow_shas, var.trusted_platform_workflow_shas)) == 0
    )
    error_message = "preview_operator_transition_workflow_shas must contain only trusted full lowercase commit SHAs."
  }
}

variable "legacy_compatibility_mode" {
  description = "Temporarily retain only constrained repository/environment Workload Identity User bindings during a verified exact-SHA migration. Broad project roles, Token Creator, and cross-boundary actAs grants are always removed. Must be false at steady state."
  type        = bool
  default     = false
}

variable "manage_automatic_default_service_account_grants_policy" {
  description = "Explicitly manage iam.automaticIamGrantsForDefaultServiceAccounts only when the project has an organization parent and the protected bootstrap identity has organization-level policy authority. Standalone projects must set false while the authoritative empty Editor binding still removes every direct Editor member."
  type        = bool
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
  default     = "Updates only the pre-created production Cloud Run service and reads its exact image repository from protected main."
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
