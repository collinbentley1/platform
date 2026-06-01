module "bootstrap" {
  source = "github.com/collinbentley1/platform//terraform/modules/bootstrap?ref=v0.1.2"

  app                   = "__APP_NAME__"
  project_id            = var.project_id
  region                = var.region
  state_bucket_name     = var.state_bucket_name
  state_bucket_location = var.state_bucket_location
  github_owner          = var.github_owner
  github_repo           = var.github_repo
  github_owner_id       = var.github_owner_id
  github_repository_id  = var.github_repository_id
  runtime_description   = "Runtime identity for the __APP_NAME__ Cloud Run services."
}
