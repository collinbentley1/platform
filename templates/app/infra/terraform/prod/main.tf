module "site" {
  source = "github.com/collinbentley1/platform//terraform/modules/cloud-run-service?ref=v0.1.0"

  providers = {
    google                = google
    google.no_attribution = google.no_attribution
  }

  app                                  = "__APP_NAME__"
  project_id                           = var.project_id
  region                               = var.region
  service_name                         = var.service_name
  artifact_registry_repository_id      = var.artifact_registry_repository_id
  artifact_registry_description        = "Container images for __APP_NAME__."
  bootstrap_image                      = var.bootstrap_image
  runtime_service_account_email        = var.runtime_service_account_email
  prod_deploy_service_account_email    = var.prod_deploy_service_account_email
  preview_deploy_service_account_email = var.preview_deploy_service_account_email
  custom_domains                       = []
}
