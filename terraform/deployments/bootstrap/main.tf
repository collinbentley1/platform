variable "repository_id" {
  description = "Immutable numeric GitHub repository ID selected by the owner-controlled bootstrap pipeline."
  type        = string

  validation {
    condition = contains([
      "1255553151",
      "711292980",
      "1025243085",
      "280932482",
    ], var.repository_id)
    error_message = "repository_id is not registered in the immutable platform bootstrap map."
  }
}

variable "active_workflow_sha" {
  description = "Exact immutable platform workflow commit supplied by the trusted pipeline context."
  type        = string

  validation {
    condition = (
      can(regex("^[0-9a-f]{40}$", var.active_workflow_sha)) &&
      !contains([
        "734d0cd02187f88c6e91263f127dc3f4c0709feb",
        "1378a3e81a5e74c71f2adfd5548b430bb008490e",
        "37bd4b1beea8802ec85c38d69ea08d5992c75a50",
        "42435a3c4c5c063a342765ef7c85047224217fe2",
        "7f01d9f008a7757df12f13ac8fa0f261600cf21a",
        "4f032955477c26b942fdd4f1b01f5272380390ea",
        "92c73184bc527388b5e10ccb5e4f0222a84e68b5",
        "33ab9b9a5f3d8a0553372980c22540cad001f776",
        "ddaa918319be123c780876d510efb4715c1f879d",
      ], var.active_workflow_sha)
    )
    error_message = "active_workflow_sha must be a reviewed full SHA and must not be a vulnerable pre-migration release."
  }
}

variable "legacy_compatibility_mode" {
  description = "Owner-selected WIF migration phase. True retains only constrained compatibility bindings; false is the required steady state."
  type        = bool
}

variable "transition_workflow_sha" {
  description = "Optional immediately previous safe platform SHA retained only during add-new/repin/verify/remove-old rollout."
  type        = string
  default     = ""

  validation {
    condition = (
      var.transition_workflow_sha == "" ||
      (
        can(regex("^[0-9a-f]{40}$", var.transition_workflow_sha)) &&
        !contains([
          "734d0cd02187f88c6e91263f127dc3f4c0709feb",
          "1378a3e81a5e74c71f2adfd5548b430bb008490e",
          "37bd4b1beea8802ec85c38d69ea08d5992c75a50",
          "42435a3c4c5c063a342765ef7c85047224217fe2",
          "7f01d9f008a7757df12f13ac8fa0f261600cf21a",
          "4f032955477c26b942fdd4f1b01f5272380390ea",
          "92c73184bc527388b5e10ccb5e4f0222a84e68b5",
          "33ab9b9a5f3d8a0553372980c22540cad001f776",
          "ddaa918319be123c780876d510efb4715c1f879d",
        ], var.transition_workflow_sha)
      )
    )
    error_message = "transition_workflow_sha must be empty or an immediately previous reviewed safe SHA, never a vulnerable pre-migration release."
  }

  validation {
    condition     = !(var.legacy_compatibility_mode && var.transition_workflow_sha != "")
    error_message = "legacy_compatibility_mode is allowed only for the initial migration with an empty transition_workflow_sha."
  }
}

locals {
  trusted_workflow_shas = toset(compact([
    var.active_workflow_sha,
    var.transition_workflow_sha,
  ]))
  preview_operations_active_workflow_shas = toset([
    var.active_workflow_sha,
  ])
  preview_operator_transition_workflow_shas = toset(compact([
    var.transition_workflow_sha,
  ]))

  deployments = {
    "1255553151" = {
      app                         = "cdbentley"
      project_id                  = "cdbentley"
      region                      = "us-east4"
      state_bucket_name           = "cdbentley-tfstate-882468538648"
      bootstrap_state_bucket_name = "cdbentley-tfstate-882468538648-bootstrap"
      state_bucket_location       = "US-EAST4"
      github_repo                 = "cdbentley"
      github_repository_id        = "1255553151"
      required_services = [
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
      runtime_project_roles = []
      runtime_description   = "Runtime identity for the cdbentley Cloud Run services."
    }
    "711292980" = {
      app                         = "runsetta"
      project_id                  = "runsetta"
      region                      = "us-east4"
      state_bucket_name           = "runsetta-tfstate-601124730704"
      bootstrap_state_bucket_name = "runsetta-tfstate-601124730704-bootstrap"
      state_bucket_location       = "US-EAST4"
      github_repo                 = "runsetta"
      github_repository_id        = "711292980"
      required_services = [
        "artifactregistry.googleapis.com",
        "cloudasset.googleapis.com",
        "cloudresourcemanager.googleapis.com",
        "iam.googleapis.com",
        "iamcredentials.googleapis.com",
        "run.googleapis.com",
        "secretmanager.googleapis.com",
        "serviceusage.googleapis.com",
        "storage.googleapis.com",
        "sts.googleapis.com",
      ]
      runtime_project_roles = []
      runtime_description   = "Runtime identity for the Runsetta Cloud Run services."
    }
    "1025243085" = {
      app                         = "medlock"
      project_id                  = "medlock-1025243085"
      region                      = "us-east4"
      state_bucket_name           = "medlock-tfstate-1025243085"
      bootstrap_state_bucket_name = "medlock-tfstate-1025243085-bootstrap"
      state_bucket_location       = "US-EAST4"
      github_repo                 = "healthmcp"
      github_repository_id        = "1025243085"
      required_services = [
        "artifactregistry.googleapis.com",
        "cloudasset.googleapis.com",
        "cloudresourcemanager.googleapis.com",
        "firestore.googleapis.com",
        "iam.googleapis.com",
        "iamcredentials.googleapis.com",
        "run.googleapis.com",
        "secretmanager.googleapis.com",
        "serviceusage.googleapis.com",
        "storage.googleapis.com",
        "sts.googleapis.com",
      ]
      runtime_project_roles = [
        "roles/datastore.user",
      ]
      runtime_description = "Runtime identity for the Medlock Cloud Run services."
    }
    "280932482" = {
      app                         = "critical-history"
      project_id                  = "critical-history-16823277"
      region                      = "us-east4"
      state_bucket_name           = "critical-history-tfstate-422714632513"
      bootstrap_state_bucket_name = "critical-history-tfstate-422714632513-bootstrap"
      state_bucket_location       = "US-EAST4"
      github_repo                 = "critical-history"
      github_repository_id        = "280932482"
      required_services = [
        "artifactregistry.googleapis.com",
        "certificatemanager.googleapis.com",
        "cloudasset.googleapis.com",
        "cloudresourcemanager.googleapis.com",
        "compute.googleapis.com",
        "iam.googleapis.com",
        "iamcredentials.googleapis.com",
        "run.googleapis.com",
        "serviceusage.googleapis.com",
        "storage.googleapis.com",
        "sts.googleapis.com",
      ]
      runtime_project_roles = []
      runtime_description   = "Runtime identity for the Critical History Cloud Run services."
    }
  }

  deployment = local.deployments[var.repository_id]
}

provider "google" {
  project = local.deployment.project_id
  region  = local.deployment.region
}

module "bootstrap" {
  source = "../../modules/bootstrap"

  app                                       = local.deployment.app
  project_id                                = local.deployment.project_id
  region                                    = local.deployment.region
  state_bucket_name                         = local.deployment.state_bucket_name
  bootstrap_state_bucket_name               = local.deployment.bootstrap_state_bucket_name
  state_bucket_location                     = local.deployment.state_bucket_location
  github_owner                              = "collinbentley1"
  github_repo                               = local.deployment.github_repo
  github_owner_id                           = "16823277"
  github_repository_id                      = local.deployment.github_repository_id
  trusted_platform_workflow_shas            = local.trusted_workflow_shas
  preview_operations_active_workflow_shas   = local.preview_operations_active_workflow_shas
  preview_operator_transition_workflow_shas = local.preview_operator_transition_workflow_shas
  legacy_compatibility_mode                 = var.legacy_compatibility_mode
  # These four personal projects have no organization parent. Google permits
  # Organization Policy Administrator only at organization scope and marks the
  # write permissions unsupported in project custom roles. The authoritative
  # empty Editor binding remains mandatory; enable this policy only after a
  # separately reviewed move into an organization.
  manage_automatic_default_service_account_grants_policy = false
  required_services                                      = local.deployment.required_services
  runtime_project_roles                                  = local.deployment.runtime_project_roles
  runtime_description                                    = local.deployment.runtime_description
}
