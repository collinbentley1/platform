variable "project_id" {
  description = "Google Cloud project containing the existing Cloud Run service."
  type        = string
}

variable "region" {
  description = "Cloud Run service region."
  type        = string
}

variable "service_name" {
  description = "Existing Cloud Run service receiving the custom domains."
  type        = string
}

variable "domains" {
  description = "Custom domains mapped to the existing production service."
  type        = set(string)

  validation {
    condition = alltrue([
      for domain in var.domains : can(regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", domain))
    ])
    error_message = "domains must contain only lower-case fully qualified DNS names."
  }
}
