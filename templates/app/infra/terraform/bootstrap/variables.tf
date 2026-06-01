variable "project_id" {
  description = "Google Cloud project ID."
  type        = string
  default     = "__PROJECT_ID__"
}

variable "region" {
  description = "Primary Google Cloud region."
  type        = string
  default     = "us-east4"
}

variable "state_bucket_name" {
  description = "Globally unique Cloud Storage bucket for Terraform state."
  type        = string
  default     = "__STATE_BUCKET__"
}

variable "state_bucket_location" {
  description = "Cloud Storage location for Terraform state."
  type        = string
  default     = "US-EAST4"
}

variable "github_owner" {
  description = "GitHub repository owner."
  type        = string
  default     = "collinbentley1"
}

variable "github_repo" {
  description = "GitHub repository name."
  type        = string
  default     = "__APP_NAME__"
}

variable "github_owner_id" {
  description = "Immutable numeric GitHub owner ID."
  type        = string
  default     = "__GITHUB_OWNER_ID__"
}

variable "github_repository_id" {
  description = "Immutable numeric GitHub repository ID."
  type        = string
  default     = "__GITHUB_REPOSITORY_ID__"
}
