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
  description = "Digest-pinned initial public image used before the application container exists."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.bootstrap_image))
    error_message = "bootstrap_image must end in an immutable sha256 digest."
  }
}

variable "bootstrap_runtime_service_account_email" {
  description = "No-role service account used only while the digest-pinned bootstrap image is active."
  type        = string
}

variable "runtime_service_account_email" {
  description = "Cloud Run runtime service account email."
  type        = string
}

variable "preview_runtime_service_account_email" {
  description = "No-data Cloud Run runtime service account email for pull request previews."
  type        = string
}

variable "preview_ingress" {
  description = "Ingress policy for the shared preview Cloud Run service. Use load-balancer-only ingress only when a protected preview frontend exists."
  type        = string
  default     = "INGRESS_TRAFFIC_ALL"

  validation {
    condition = contains([
      "INGRESS_TRAFFIC_ALL",
      "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
    ], var.preview_ingress)
    error_message = "preview_ingress must allow all traffic or only internal and Cloud Load Balancing traffic."
  }
}

variable "prod_deploy_service_account_email" {
  description = "Production deploy service account email; receives service update, exact runtime actAs, and exact-repository Artifact Registry Reader only."
  type        = string
}

variable "prod_publisher_service_account_email" {
  description = "Artifact Registry-only production publisher service account email."
  type        = string
}

variable "preview_deploy_service_account_email" {
  description = "Preview deploy service account email; receives service update, exact runtime actAs, and exact-repository Artifact Registry Reader only."
  type        = string
}

variable "preview_operator_service_account_email" {
  description = "Preview traffic operator service account email; receives service update only, with no Artifact Registry or runtime actAs grant."
  type        = string
}

variable "preview_publisher_service_account_email" {
  description = "Artifact Registry-only preview publisher service account email."
  type        = string
}

variable "container_env" {
  description = "Bootstrap container environment variables. Deploy workflows own later runtime env drift."
  type        = map(string)
  default     = {}
}

variable "runtime_secret_ids" {
  description = "Secret Manager secret containers managed by the platform. Declaring a container does not grant the runtime access."
  type        = set(string)
  default     = []
}

variable "runtime_secret_accessor_ids" {
  description = "Declared runtime secret IDs whose payloads the production runtime may read. Secure default is no access."
  type        = set(string)
  default     = []

  validation {
    condition     = length(setsubtract(var.runtime_secret_accessor_ids, var.runtime_secret_ids)) == 0
    error_message = "runtime_secret_accessor_ids must be a subset of runtime_secret_ids."
  }
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
