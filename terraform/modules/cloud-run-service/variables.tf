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

variable "service_name" {
  description = "Production Cloud Run service name."
  type        = string
}

variable "artifact_registry_repository_id" {
  description = "Artifact Registry Docker repository ID."
  type        = string
}

variable "artifact_registry_description" {
  description = "Artifact Registry repository description."
  type        = string
}

variable "bootstrap_image" {
  description = "Initial public image used before the application container exists."
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "runtime_service_account_email" {
  description = "Cloud Run runtime service account email."
  type        = string
}

variable "prod_deploy_service_account_email" {
  description = "Production deploy service account email."
  type        = string
}

variable "preview_deploy_service_account_email" {
  description = "Preview deploy service account email."
  type        = string
}

variable "custom_domains" {
  description = "Cloud Run custom domains mapped to the production service."
  type        = set(string)
  default     = []
}

variable "container_env" {
  description = "Bootstrap container environment variables. Deploy workflows own later runtime env drift."
  type        = map(string)
  default     = {}
}

variable "runtime_secret_ids" {
  description = "Secret Manager secret IDs created for the runtime service account."
  type        = set(string)
  default     = []
}

variable "firestore_database" {
  description = "Optional Firestore native database."
  type = object({
    name                              = string
    location_id                       = string
    runtime_collection_env_name       = optional(string)
    runtime_collection_env_value      = optional(string)
    point_in_time_recovery_enablement = optional(string, "POINT_IN_TIME_RECOVERY_DISABLED")
  })
  default = null
}

variable "labels" {
  description = "Additional labels merged with the platform labels."
  type        = map(string)
  default     = {}
}
