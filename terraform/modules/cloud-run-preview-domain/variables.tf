variable "project_id" {
  description = "Google Cloud project containing the shared preview service and load balancer."
  type        = string
}

variable "region" {
  description = "Region containing the shared preview Cloud Run service."
  type        = string
}

variable "preview_service_name" {
  description = "Existing shared Cloud Run service whose traffic tags identify pull request previews."
  type        = string

  validation {
    condition     = can(regex("^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$", var.preview_service_name))
    error_message = "preview_service_name must be a valid Cloud Run service name."
  }
}

variable "preview_domain" {
  description = "Base domain below which pr-N hostnames route to matching Cloud Run traffic tags."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", var.preview_domain))
    error_message = "preview_domain must be a lower-case fully qualified DNS name."
  }
}

variable "resource_name_prefix" {
  description = "Short stable prefix for the preview routing resources."
  type        = string

  validation {
    condition     = can(regex("^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$", var.resource_name_prefix))
    error_message = "resource_name_prefix must be 1-32 lower-case RFC1035 characters."
  }
}
