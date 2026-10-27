terraform {
  required_version = "~> 1.14.0"
  backend "gcs" {}
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 7.45.0"
    }
  }
}

variable "project_id" { type = string }
variable "initial_images" { type = map(string) }

locals {
  catalog             = jsondecode(file("${path.module}/../projects.json"))
  apps                = { for app in local.catalog.projects : app.name => app if app.project == var.project_id }
  registries          = toset([for app in local.apps : app.registry])
  secrets             = merge({}, [for name, app in local.apps : { for key, version in app.secrets : "${name}/${key}" => { app = name, id = split(":", version)[0] } }]...)
  data_enabled        = anytrue([for app in local.apps : app.data])
  identity_enabled    = anytrue([for app in local.apps : try(app.identity, false)])
  authority_workflows = ["deliver.yml", "reconcile-v1.yml"]
}

provider "google" {
  project               = var.project_id
  billing_project       = var.project_id
  user_project_override = true
}

resource "google_project_service" "services" {
  for_each           = toset(concat(["cloudresourcemanager.googleapis.com", "run.googleapis.com", "artifactregistry.googleapis.com", "containerscanning.googleapis.com", "containeranalysis.googleapis.com", "iam.googleapis.com", "iamcredentials.googleapis.com", "sts.googleapis.com", "monitoring.googleapis.com"], local.data_enabled ? ["firestore.googleapis.com"] : [], local.identity_enabled ? ["identitytoolkit.googleapis.com", "apikeys.googleapis.com"] : [], length(local.secrets) > 0 ? ["secretmanager.googleapis.com"] : [], contains(keys(local.apps), "healthmcp") ? ["identitytoolkit.googleapis.com", "recaptchaenterprise.googleapis.com", "secretmanager.googleapis.com"] : []))
  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

resource "google_iam_workload_identity_pool" "delivery" {
  project                   = var.project_id
  workload_identity_pool_id = "platform-delivery"
  display_name              = "Reviewed platform delivery"
  depends_on                = [google_project_service.services]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.delivery.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  attribute_mapping = {
    "google.subject"      = "assertion.sub"
    "attribute.authority" = "assertion.workflow_ref + ':' + assertion.environment"
  }
  attribute_condition = "assertion.repository_id == '1255856466' && assertion.repository_owner_id == '16823277' && assertion.ref == 'refs/heads/main' && assertion.runner_environment == 'github-hosted' && assertion.event_name in ['push', 'schedule', 'workflow_dispatch'] && assertion.workflow_ref in ['collinbentley1/platform/.github/workflows/deliver.yml@refs/heads/main', 'collinbentley1/platform/.github/workflows/reconcile-v1.yml@refs/heads/main']"
  oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
}

resource "google_service_account" "publish" {
  account_id = "platform-publish"
  depends_on = [google_project_service.services]
}
resource "google_service_account" "deploy" {
  account_id = "platform-deploy"
  depends_on = [google_project_service.services]
}
resource "google_service_account" "audit" {
  account_id = "platform-audit"
  depends_on = [google_project_service.services]
}
resource "google_service_account" "runtime" {
  for_each   = local.apps
  account_id = "runtime-${substr(each.value.service, 0, 20)}"
  depends_on = [google_project_service.services]
}
resource "google_service_account" "preview" {
  for_each   = local.apps
  account_id = "preview-${substr(each.value.service, 0, 20)}"
  depends_on = [google_project_service.services]
}

resource "google_service_account_iam_member" "publish_wif" {
  for_each           = local.apps
  service_account_id = google_service_account.publish.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.delivery.name}/attribute.authority/collinbentley1/platform/.github/workflows/deliver.yml@refs/heads/main:publish-${each.key}"
}
resource "google_service_account_iam_member" "deploy_wif" {
  for_each           = local.apps
  service_account_id = google_service_account.deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.delivery.name}/attribute.authority/collinbentley1/platform/.github/workflows/deliver.yml@refs/heads/main:deploy-${each.key}"
}
resource "google_service_account_iam_member" "audit_wif" {
  for_each           = local.apps
  service_account_id = google_service_account.audit.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.delivery.name}/attribute.authority/collinbentley1/platform/.github/workflows/reconcile-v1.yml@refs/heads/main:audit-${each.key}"
}
resource "google_artifact_registry_repository" "images" {
  for_each      = local.registries
  project       = var.project_id
  location      = "us-east4"
  repository_id = each.key
  format        = "DOCKER"
  docker_config { immutable_tags = true }
  depends_on = [google_project_service.services]
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [description, cleanup_policies, cleanup_policy_dry_run]
  }
}
resource "google_artifact_registry_repository_iam_member" "publish" {
  for_each   = local.registries
  location   = "us-east4"
  repository = google_artifact_registry_repository.images[each.key].repository_id
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.publish.email}"
}
resource "google_artifact_registry_repository_iam_member" "deploy" {
  for_each   = local.registries
  location   = "us-east4"
  repository = google_artifact_registry_repository.images[each.key].repository_id
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.deploy.email}"
}

resource "google_artifact_registry_repository_iam_member" "audit" {
  for_each   = local.registries
  location   = "us-east4"
  repository = google_artifact_registry_repository.images[each.key].repository_id
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.audit.email}"
}

resource "google_project_iam_custom_role" "deploy" {
  role_id     = "platformServiceUpdate"
  title       = "Update the reviewed application service"
  permissions = ["run.services.get", "run.services.update"]
  depends_on  = [google_project_service.services]
}
resource "google_project_iam_custom_role" "read" {
  role_id     = "platformDeliveryRead"
  title       = "Read deployment and vulnerability status"
  permissions = ["run.services.get", "run.revisions.get", "run.operations.get", "containeranalysis.occurrences.get", "containeranalysis.occurrences.list"]
  depends_on  = [google_project_service.services]
}
resource "google_project_iam_member" "read" {
  for_each = { deploy = google_service_account.deploy.email, audit = google_service_account.audit.email }
  project  = var.project_id
  role     = google_project_iam_custom_role.read.name
  member   = "serviceAccount:${each.value}"
}
resource "google_service_account_iam_member" "runtime_act_as" {
  for_each           = local.apps
  service_account_id = google_service_account.runtime[each.key].name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.deploy.email}"
}
resource "google_service_account_iam_member" "preview_act_as" {
  for_each           = local.apps
  service_account_id = google_service_account.preview[each.key].name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.deploy.email}"
}
resource "google_project_iam_member" "data" {
  for_each = { for name, app in local.apps : name => app if app.data }
  project  = var.project_id
  role     = "roles/datastore.user"
  member   = "serviceAccount:${google_service_account.runtime[each.key].email}"
  condition {
    title      = "application-database"
    expression = "resource.name.startsWith('projects/${var.project_id}/databases/(default)')"
  }
}
resource "google_secret_manager_secret_iam_member" "runtime" {
  for_each  = local.secrets
  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime[each.value.app].email}"
}

resource "google_project_iam_custom_role" "waitlist" {
  count       = contains(keys(local.apps), "healthmcp") ? 1 : 0
  project     = var.project_id
  role_id     = "platformWaitlistSender"
  title       = "Waitlist ownership runtime"
  permissions = ["firebaseauth.users.sendEmail", "serviceusage.services.use", "recaptchaenterprise.assessments.create"]
}
resource "google_project_iam_member" "waitlist" {
  count   = contains(keys(local.apps), "healthmcp") ? 1 : 0
  project = var.project_id
  role    = google_project_iam_custom_role.waitlist[0].name
  member  = "serviceAccount:${google_service_account.runtime["healthmcp"].email}"
}

resource "google_cloud_run_v2_service" "app" {
  for_each             = local.apps
  name                 = each.value.service
  location             = each.value.region
  deletion_protection  = true
  invoker_iam_disabled = true
  scaling {
    min_instance_count = 0
    max_instance_count = local.catalog.defaults.productionMaxInstances
  }
  template {
    service_account = google_service_account.runtime[each.key].email
    scaling {
      min_instance_count = 0
      max_instance_count = local.catalog.defaults.productionMaxInstances
    }
    containers {
      image = var.initial_images[each.key]
      ports { container_port = 8080 }
      resources { limits = { cpu = "1", memory = "512Mi" } }
    }
  }
  lifecycle { ignore_changes = [ingress, template[0].service_account, template[0].containers[0].image, template[0].containers[0].env, template[0].labels, traffic, labels, client, client_version] }
}
resource "google_cloud_run_v2_service" "preview" {
  for_each             = local.apps
  name                 = "${each.value.service}-preview-v1"
  location             = each.value.region
  deletion_protection  = false
  invoker_iam_disabled = false
  scaling {
    min_instance_count = 0
    max_instance_count = local.catalog.defaults.previewMaxInstances
  }
  template {
    service_account = google_service_account.preview[each.key].email
    scaling {
      min_instance_count = 0
      max_instance_count = local.catalog.defaults.previewMaxInstances
    }
    containers {
      image = var.initial_images[each.key]
      ports { container_port = 8080 }
      resources { limits = { cpu = "1", memory = "512Mi" } }
    }
  }
  lifecycle { ignore_changes = [template[0].containers[0].image, template[0].containers[0].env, template[0].labels, traffic, labels, client, client_version] }
}
resource "google_cloud_run_v2_service_iam_member" "deploy" {
  for_each = local.apps
  name     = google_cloud_run_v2_service.app[each.key].name
  location = each.value.region
  role     = google_project_iam_custom_role.deploy.name
  member   = "serviceAccount:${google_service_account.deploy.email}"
}
resource "google_cloud_run_v2_service_iam_member" "preview_deploy" {
  for_each = local.apps
  name     = google_cloud_run_v2_service.preview[each.key].name
  location = each.value.region
  role     = google_project_iam_custom_role.deploy.name
  member   = "serviceAccount:${google_service_account.deploy.email}"
}
resource "google_cloud_run_v2_service_iam_member" "preview_invoke" {
  for_each = local.apps
  name     = google_cloud_run_v2_service.preview[each.key].name
  location = each.value.region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.deploy.email}"
}

resource "google_identity_platform_config" "identity" {
  count              = local.identity_enabled ? 1 : 0
  project            = var.project_id
  authorized_domains = distinct(concat(["localhost", "${var.project_id}.firebaseapp.com"], [for app in local.apps : replace(try(app.env.PUBLIC_ORIGIN, "https://${app.service}-${app.number}.${app.region}.run.app"), "https://", "") if try(app.identity, false)]))
  sign_in {
    phone_number { enabled = false }
    email {
      enabled           = true
      password_required = true
    }
  }
  depends_on = [google_project_service.services]
}

resource "google_project_iam_custom_role" "identity_runtime" {
  count       = local.identity_enabled ? 1 : 0
  role_id     = "platformAccountLifecycle"
  title       = "Managed application account lifecycle"
  permissions = ["firebaseauth.users.get", "firebaseauth.users.update", "firebaseauth.users.delete", "serviceusage.services.use"]
  depends_on  = [google_project_service.services]
}
resource "google_project_iam_member" "identity_runtime" {
  for_each = { for name, app in local.apps : name => app if try(app.identity, false) }
  project  = var.project_id
  role     = google_project_iam_custom_role.identity_runtime[0].name
  member   = "serviceAccount:${google_service_account.runtime[each.key].email}"
}
resource "google_apikeys_key" "identity" {
  count        = local.identity_enabled ? 1 : 0
  project      = var.project_id
  name         = "platform-identity"
  display_name = "Public Identity Platform client"
  restrictions {
    api_targets { service = "identitytoolkit.googleapis.com" }
  }
  depends_on = [google_project_service.services]
}
output "identity_api_key" {
  value     = try(google_apikeys_key.identity[0].key_string, null)
  sensitive = true
}

resource "google_firestore_database" "application" {
  count                             = local.data_enabled ? 1 : 0
  project                           = var.project_id
  name                              = "(default)"
  location_id                       = var.project_id == "medlock-1025243085" ? "nam5" : "us-east4"
  type                              = "FIRESTORE_NATIVE"
  concurrency_mode                  = "OPTIMISTIC"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"
  delete_protection_state           = "DELETE_PROTECTION_ENABLED"
  depends_on                        = [google_project_service.services]
  lifecycle { prevent_destroy = true }
}
resource "google_firestore_backup_schedule" "daily" {
  count     = local.data_enabled ? 1 : 0
  project   = var.project_id
  database  = google_firestore_database.application[0].name
  retention = "604800s"
  daily_recurrence {}
}

resource "google_firestore_field" "waitlist_expiry" {
  for_each   = contains(keys(local.apps), "healthmcp") ? toset(["waitlist", "waitlist_quota"]) : toset([])
  project    = var.project_id
  database   = google_firestore_database.application[0].name
  collection = each.value
  field      = "expiresAt"
  ttl_config {}
  index_config {}
}

resource "google_identity_platform_config" "waitlist" {
  count   = contains(keys(local.apps), "healthmcp") ? 1 : 0
  project = var.project_id
  sign_in {
    phone_number { enabled = false }
    allow_duplicate_emails = false
    email {
      enabled           = true
      password_required = false
    }
  }
  authorized_domains = ["medlock.ai", "www.medlock.ai"]
  depends_on         = [google_project_service.services]
}

resource "google_recaptcha_enterprise_key" "waitlist" {
  count           = contains(keys(local.apps), "healthmcp") ? 1 : 0
  project         = var.project_id
  display_name    = "Medlock waitlist ownership"
  deletion_policy = "PREVENT"
  web_settings {
    integration_type  = "SCORE"
    allow_all_domains = false
    allow_amp_traffic = false
    allowed_domains   = ["medlock.ai"]
  }
  depends_on = [google_project_service.services]
}
output "waitlist_site_key" {
  value = try(google_recaptcha_enterprise_key.waitlist[0].name, null)
}

resource "google_firestore_field" "visits_expiry" {
  count      = contains(keys(local.apps), "virtual-care-mcp") ? 1 : 0
  project    = var.project_id
  database   = google_firestore_database.application[0].name
  collection = "visits"
  field      = "expiresAt"
  ttl_config {}
  index_config {}
}
