data "google_project" "current" {
  project_id = var.project_id
}

locals {
  github_repo_full_name  = "${var.github_owner}/${var.github_repo}"
  workload_identity_pool = "projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.github.workload_identity_pool_id}"

  github_repo_principal_set = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.repository_id/${var.github_repository_id}"

  # Rename-proof production binding. The pool's attribute_condition already restricts entry to this
  # one repository by immutable numeric id, so keying on attribute.environment/production means
  # exactly "this repository's production environment" without embedding the repository name (which
  # a rename would break, as the medlock->healthmcp rename did). GitHub environment protection rules
  # still gate which jobs may assume the production environment.
  github_prod_principal_set = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.environment/production"

  labels = {
    app        = var.app
    managed-by = "terraform"
  }

  service_accounts = {
    prod    = google_service_account.prod_deploy.email
    preview = google_service_account.preview_deploy.email
  }
}

resource "google_project_service" "required" {
  for_each = var.required_services

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_storage_bucket" "terraform_state" {
  name                        = var.state_bucket_name
  project                     = var.project_id
  location                    = var.state_bucket_location
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  logging {
    log_bucket        = google_storage_bucket.terraform_state_access_logs.name
    log_object_prefix = "terraform-state/"
  }

  versioning {
    enabled = true
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }

    condition {
      age                   = 90
      matches_storage_class = ["STANDARD"]
      num_newer_versions    = 20
      with_state            = "ARCHIVED"
    }
  }

  labels = local.labels

  depends_on = [
    google_project_service.required,
    google_storage_bucket_iam_member.terraform_state_access_logs_writer,
  ]
}

resource "google_storage_bucket" "terraform_state_access_logs" {
  #checkov:skip=CKV_GCP_62:This bucket is the sink for Terraform state access logs.
  name                        = "${var.state_bucket_name}-access-logs"
  project                     = var.project_id
  location                    = var.state_bucket_location
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }

    condition {
      age                   = 365
      matches_storage_class = ["STANDARD"]
    }
  }

  labels = merge(local.labels, { purpose = "terraform-state-access-logs" })

  depends_on = [google_project_service.required]
}

resource "google_storage_bucket_iam_member" "terraform_state_access_logs_writer" {
  bucket = google_storage_bucket.terraform_state_access_logs.name
  role   = "roles/storage.objectCreator"
  member = "group:cloud-storage-analytics@google.com"
}

resource "google_iam_workload_identity_pool" "github" {
  project                   = var.project_id
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
  description               = "GitHub Actions OIDC identities for ${local.github_repo_full_name}."

  depends_on = [google_project_service.required]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  display_name                       = "GitHub"
  description                        = "OIDC provider restricted to ${local.github_repo_full_name}."

  attribute_mapping = {
    "attribute.ref"                 = "assertion.ref"
    "attribute.repository_id"       = "assertion.repository_id"
    "attribute.repository_owner_id" = "assertion.repository_owner_id"
    # environment is an optional OIDC claim (absent on pull_request / preview / validate tokens);
    # the has() guard keeps CEL evaluation from failing for those exchanges, which would break
    # preview auth. Present only on jobs running in a GitHub environment (e.g. production).
    "attribute.environment" = "has(assertion.environment) ? assertion.environment : ''"
    "google.subject"        = "assertion.sub"
  }

  attribute_condition = "assertion.repository_owner_id == '${var.github_owner_id}' && assertion.repository_id == '${var.github_repository_id}'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com/"
  }
}

resource "google_service_account" "terraform" {
  project      = var.project_id
  account_id   = "gha-terraform"
  display_name = "GitHub Actions Terraform"
  description  = var.terraform_service_account_description

  depends_on = [google_project_service.required]
}

resource "google_service_account" "prod_deploy" {
  project      = var.project_id
  account_id   = "gha-prod-deploy"
  display_name = "GitHub Actions Production Deploy"
  description  = var.prod_deploy_service_account_description

  depends_on = [google_project_service.required]
}

resource "google_service_account" "preview_deploy" {
  project      = var.project_id
  account_id   = "gha-preview-deploy"
  display_name = "GitHub Actions Preview Deploy"
  description  = var.preview_deploy_service_account_description

  depends_on = [google_project_service.required]
}

resource "google_service_account" "runtime" {
  project      = var.project_id
  account_id   = "cloud-run-runtime"
  display_name = var.runtime_display_name
  description  = var.runtime_description

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "terraform_project_roles" {
  for_each = var.terraform_project_roles

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.terraform.email}"
}

resource "google_project_iam_member" "deploy_project_roles" {
  for_each = var.deploy_project_roles

  project = var.project_id
  role    = each.value.role
  member  = "serviceAccount:${local.service_accounts[each.value.target]}"
}

resource "google_storage_bucket_iam_member" "terraform_state_admin" {
  bucket = google_storage_bucket.terraform_state.name
  role   = "roles/storage.admin"
  member = "serviceAccount:${google_service_account.terraform.email}"
}

resource "google_service_account_iam_member" "terraform_uses_runtime" {
  service_account_id = google_service_account.runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.terraform.email}"
}

resource "google_service_account_iam_member" "prod_deploy_uses_runtime" {
  service_account_id = google_service_account.runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.prod_deploy.email}"
}

resource "google_service_account_iam_member" "preview_deploy_uses_runtime" {
  service_account_id = google_service_account.runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.preview_deploy.email}"
}

resource "google_service_account_iam_member" "terraform_self_token_creator" {
  service_account_id = google_service_account.terraform.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.terraform.email}"
}

resource "google_service_account_iam_member" "prod_deploy_self_token_creator" {
  service_account_id = google_service_account.prod_deploy.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.prod_deploy.email}"
}

resource "google_service_account_iam_member" "preview_deploy_self_token_creator" {
  service_account_id = google_service_account.preview_deploy.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.preview_deploy.email}"
}

# Rename-proof production bindings. Keyed on attribute.environment/production rather than the OIDC
# subject (which embeds the repo name and broke on the medlock->healthmcp rename). The pool
# attribute_condition already restricts entry to one repository by immutable numeric id.
resource "google_service_account_iam_member" "terraform_wif_prod_env" {
  service_account_id = google_service_account.terraform.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.github_prod_principal_set
}

resource "google_service_account_iam_member" "terraform_wif_prod_env_token_creator" {
  service_account_id = google_service_account.terraform.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = local.github_prod_principal_set
}

resource "google_service_account_iam_member" "prod_deploy_wif_prod_env" {
  service_account_id = google_service_account.prod_deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.github_prod_principal_set
}

resource "google_service_account_iam_member" "prod_deploy_wif_prod_env_token_creator" {
  service_account_id = google_service_account.prod_deploy.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = local.github_prod_principal_set
}

resource "google_service_account_iam_member" "preview_deploy_wif_repo" {
  service_account_id = google_service_account.preview_deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.github_repo_principal_set
}

resource "google_service_account_iam_member" "preview_deploy_wif_repo_token_creator" {
  service_account_id = google_service_account.preview_deploy.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = local.github_repo_principal_set
}
