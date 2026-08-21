variable "repository_id" {
  description = "Immutable numeric GitHub repository ID selected by the trusted reusable workflow."
  type        = string

  validation {
    condition = contains([
      "1255553151",
      "711292980",
      "1025243085",
      "280932482",
    ], var.repository_id)
    error_message = "repository_id is not registered in the immutable platform deployment map."
  }
}

locals {
  bootstrap_image = "us-docker.pkg.dev/cloudrun/container/hello@sha256:9a0e9a5c7a19281e7617991d2fc61809de4973e6e75a10b2f07df3719ffda33c"

  deployments = {
    "1255553151" = {
      app                               = "cdbentley"
      project_id                        = "cdbentley"
      region                            = "us-east4"
      service_name                      = "cdbentley"
      artifact_registry_repository_id   = "site"
      artifact_registry_description     = "Container images for the cdbentley personal site."
      container_env                     = {}
      runtime_secret_ids                = []
      runtime_secret_accessor_ids       = []
      firestore_database                = null
      bootstrap_runtime_service_account = "cloud-run-bootstrap@cdbentley.iam.gserviceaccount.com"
      runtime_service_account           = "cloud-run-runtime@cdbentley.iam.gserviceaccount.com"
      preview_runtime_service_account   = "cloud-run-preview@cdbentley.iam.gserviceaccount.com"
      prod_deploy_service_account       = "gha-prod-deploy@cdbentley.iam.gserviceaccount.com"
      prod_publisher_service_account    = "gha-prod-publish@cdbentley.iam.gserviceaccount.com"
      preview_deploy_service_account    = "gha-preview-deploy@cdbentley.iam.gserviceaccount.com"
      preview_operator_service_account  = "gha-preview-operator@cdbentley.iam.gserviceaccount.com"
      preview_publisher_service_account = "gha-preview-publish@cdbentley.iam.gserviceaccount.com"
    }
    "711292980" = {
      app                             = "runsetta"
      project_id                      = "runsetta"
      region                          = "us-east4"
      service_name                    = "runsetta"
      artifact_registry_repository_id = "api"
      artifact_registry_description   = "Container images for the Runsetta API."
      container_env = {
        RUNSETTA_OFFLINE   = "1"
        RUNSETTA_TTS_MODEL = "gpt-4o-mini-tts"
        RUNSETTA_TTS_VOICE = "marin"
      }
      runtime_secret_ids = [
        "openai-api-key",
        "spotify-client-id",
        "spotify-client-secret",
        "spotify-redirect-uri",
      ]
      # Keep the existing secret containers, but the deliberately offline
      # runtime may not read their payloads until reviewed numeric versions are
      # encoded in the platform deployment policy.
      runtime_secret_accessor_ids       = []
      firestore_database                = null
      bootstrap_runtime_service_account = "cloud-run-bootstrap@runsetta.iam.gserviceaccount.com"
      runtime_service_account           = "cloud-run-runtime@runsetta.iam.gserviceaccount.com"
      preview_runtime_service_account   = "cloud-run-preview@runsetta.iam.gserviceaccount.com"
      prod_deploy_service_account       = "gha-prod-deploy@runsetta.iam.gserviceaccount.com"
      prod_publisher_service_account    = "gha-prod-publish@runsetta.iam.gserviceaccount.com"
      preview_deploy_service_account    = "gha-preview-deploy@runsetta.iam.gserviceaccount.com"
      preview_operator_service_account  = "gha-preview-operator@runsetta.iam.gserviceaccount.com"
      preview_publisher_service_account = "gha-preview-publish@runsetta.iam.gserviceaccount.com"
    }
    "1025243085" = {
      app                             = "medlock"
      project_id                      = "medlock-1025243085"
      region                          = "us-east4"
      service_name                    = "medlock"
      artifact_registry_repository_id = "site"
      artifact_registry_description   = "Container images for Medlock."
      container_env = {
        ALLOWED_HOSTS    = "medlock.ai,www.medlock.ai,mcp.medlock.ai,healthmcp.ai,www.healthmcp.ai,healthmcp.app,www.healthmcp.app,*.run.app"
        ALLOWED_ORIGINS  = "https://medlock.ai,https://www.medlock.ai,https://mcp.medlock.ai,https://chat.openai.com,https://claude.ai,https://*.run.app"
        CANONICAL_HOST   = "medlock.ai"
        LEGACY_HOSTS     = "healthmcp.ai,www.healthmcp.ai,healthmcp.app,www.healthmcp.app"
        MEDLOCK_VERSION  = "0.2.0"
        WAITLIST_BACKEND = "firestore"
      }
      runtime_secret_ids          = []
      runtime_secret_accessor_ids = []
      firestore_database = {
        name                         = "(default)"
        location_id                  = "nam5"
        runtime_collection_env_name  = "FIRESTORE_COLLECTION"
        runtime_collection_env_value = "waitlist"
      }
      bootstrap_runtime_service_account = "cloud-run-bootstrap@medlock-1025243085.iam.gserviceaccount.com"
      runtime_service_account           = "cloud-run-runtime@medlock-1025243085.iam.gserviceaccount.com"
      preview_runtime_service_account   = "cloud-run-preview@medlock-1025243085.iam.gserviceaccount.com"
      prod_deploy_service_account       = "gha-prod-deploy@medlock-1025243085.iam.gserviceaccount.com"
      prod_publisher_service_account    = "gha-prod-publish@medlock-1025243085.iam.gserviceaccount.com"
      preview_deploy_service_account    = "gha-preview-deploy@medlock-1025243085.iam.gserviceaccount.com"
      preview_operator_service_account  = "gha-preview-operator@medlock-1025243085.iam.gserviceaccount.com"
      preview_publisher_service_account = "gha-preview-publish@medlock-1025243085.iam.gserviceaccount.com"
    }
    "280932482" = {
      app                               = "critical-history"
      project_id                        = "critical-history-16823277"
      region                            = "us-east4"
      service_name                      = "critical-history"
      artifact_registry_repository_id   = "site"
      artifact_registry_description     = "Container images for the Critical History Map."
      container_env                     = {}
      runtime_secret_ids                = []
      runtime_secret_accessor_ids       = []
      firestore_database                = null
      bootstrap_runtime_service_account = "cloud-run-bootstrap@critical-history-16823277.iam.gserviceaccount.com"
      runtime_service_account           = "cloud-run-runtime@critical-history-16823277.iam.gserviceaccount.com"
      preview_runtime_service_account   = "cloud-run-preview@critical-history-16823277.iam.gserviceaccount.com"
      prod_deploy_service_account       = "gha-prod-deploy@critical-history-16823277.iam.gserviceaccount.com"
      prod_publisher_service_account    = "gha-prod-publish@critical-history-16823277.iam.gserviceaccount.com"
      preview_deploy_service_account    = "gha-preview-deploy@critical-history-16823277.iam.gserviceaccount.com"
      preview_operator_service_account  = "gha-preview-operator@critical-history-16823277.iam.gserviceaccount.com"
      preview_publisher_service_account = "gha-preview-publish@critical-history-16823277.iam.gserviceaccount.com"
    }
  }

  deployment = local.deployments[var.repository_id]
}

provider "google" {
  project = local.deployment.project_id
  region  = local.deployment.region
}

module "site" {
  source = "../../modules/cloud-run-service"

  app                                     = local.deployment.app
  project_id                              = local.deployment.project_id
  region                                  = local.deployment.region
  service_name                            = local.deployment.service_name
  artifact_registry_repository_id         = local.deployment.artifact_registry_repository_id
  artifact_registry_description           = local.deployment.artifact_registry_description
  bootstrap_image                         = local.bootstrap_image
  bootstrap_runtime_service_account_email = local.deployment.bootstrap_runtime_service_account
  runtime_service_account_email           = local.deployment.runtime_service_account
  preview_runtime_service_account_email   = local.deployment.preview_runtime_service_account
  prod_deploy_service_account_email       = local.deployment.prod_deploy_service_account
  prod_publisher_service_account_email    = local.deployment.prod_publisher_service_account
  preview_deploy_service_account_email    = local.deployment.preview_deploy_service_account
  preview_operator_service_account_email  = local.deployment.preview_operator_service_account
  preview_publisher_service_account_email = local.deployment.preview_publisher_service_account
  container_env                           = local.deployment.container_env
  runtime_secret_ids                      = local.deployment.runtime_secret_ids
  runtime_secret_accessor_ids             = local.deployment.runtime_secret_accessor_ids
  firestore_database                      = local.deployment.firestore_database
}
