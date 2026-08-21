variable "repository_id" {
  description = "Immutable numeric GitHub repository ID selected by the owner-controlled protected pipeline."
  type        = string

  validation {
    condition = contains([
      "1255553151",
      "711292980",
      "1025243085",
      "280932482",
    ], var.repository_id)
    error_message = "repository_id is not registered in the immutable platform exposure map."
  }
}

locals {
  deployments = {
    "1255553151" = {
      project_id   = "cdbentley"
      region       = "us-east4"
      service_name = "cdbentley"
      domains      = ["cdbentley.com", "www.cdbentley.com"]
    }
    "711292980" = {
      project_id   = "runsetta"
      region       = "us-east4"
      service_name = "runsetta"
      domains      = ["runsetta.com", "www.runsetta.com"]
    }
    "1025243085" = {
      project_id   = "medlock-1025243085"
      region       = "us-east4"
      service_name = "medlock"
      domains = [
        "medlock.ai",
        "www.medlock.ai",
        "mcp.medlock.ai",
        "healthmcp.ai",
        "www.healthmcp.ai",
        "healthmcp.app",
        "www.healthmcp.app",
      ]
    }
    "280932482" = {
      project_id   = "critical-history-16823277"
      region       = "us-east4"
      service_name = "critical-history"
      domains      = ["ycriticalhistory.org", "www.ycriticalhistory.org"]
    }
  }

  deployment = local.deployments[var.repository_id]
}

provider "google" {
  project                         = local.deployment.project_id
  region                          = local.deployment.region
  add_terraform_attribution_label = false
}

module "domains" {
  source = "../../modules/cloud-run-domains"

  project_id   = local.deployment.project_id
  region       = local.deployment.region
  service_name = local.deployment.service_name
  domains      = local.deployment.domains
}

module "preview_domain" {
  for_each = var.repository_id == "280932482" ? toset(["preview.ycriticalhistory.org"]) : toset([])
  source   = "../../modules/cloud-run-preview-domain"

  project_id           = local.deployment.project_id
  region               = local.deployment.region
  preview_service_name = "${local.deployment.service_name}-preview"
  preview_domain       = each.value
  resource_name_prefix = "${local.deployment.service_name}-preview"
}
