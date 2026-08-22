data "google_project" "current" {
  project_id = var.project_id
}

locals {
  github_repo_full_name  = "${var.github_owner}/${var.github_repo}"
  workload_identity_pool = "projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.github.workload_identity_pool_id}"

  legacy_preview_deploy_principal_set   = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.legacy_preview_deploy/${var.github_repository_id}"
  legacy_preview_operator_principal_set = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.legacy_preview_operator/${var.github_repository_id}"
  legacy_prod_deploy_principal_set      = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.legacy_prod_deploy/${var.github_repository_id}"
  legacy_terraform_principal_set        = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.legacy_terraform/${var.github_repository_id}"

  preview_deploy_workflow_condition = "assertion.job_workflow_ref == 'collinbentley1/platform/.github/workflows/deploy-preview.yml@' + assertion.job_workflow_sha && assertion.event_name == 'pull_request_target' && assertion.ref == 'refs/heads/main' && assertion.base_ref == 'main' && assertion.actor != 'dependabot[bot]' && assertion.environment == 'preview-cloud'"
  preview_operator_workflow_condition = join(" || ", [
    "assertion.job_workflow_ref == 'collinbentley1/platform/.github/workflows/deploy-preview.yml@' + assertion.job_workflow_sha && assertion.event_name == 'pull_request_target' && assertion.ref == 'refs/heads/main' && assertion.base_ref == 'main' && assertion.actor != 'dependabot[bot]' && assertion.environment == 'preview-operations'",
    "assertion.job_workflow_ref == 'collinbentley1/platform/.github/workflows/cleanup-preview.yml@' + assertion.job_workflow_sha && assertion.event_name == 'pull_request_target' && assertion.ref == 'refs/heads/main' && assertion.base_ref == 'main' && assertion.environment == 'preview-operations'",
    "assertion.job_workflow_ref == 'collinbentley1/platform/.github/workflows/reconcile-previews.yml@' + assertion.job_workflow_sha && (assertion.event_name == 'push' || assertion.event_name == 'schedule' || assertion.event_name == 'workflow_dispatch') && assertion.ref == 'refs/heads/main' && assertion.environment == 'preview-operations'",
  ])
  preview_publish_workflow_condition    = "assertion.job_workflow_ref == 'collinbentley1/platform/.github/workflows/deploy-preview.yml@' + assertion.job_workflow_sha && assertion.event_name == 'pull_request_target' && assertion.ref == 'refs/heads/main' && assertion.base_ref == 'main' && assertion.actor != 'dependabot[bot]' && assertion.environment == 'preview-publish'"
  production_workflow_condition         = "assertion.job_workflow_ref == 'collinbentley1/platform/.github/workflows/deploy-prod.yml@' + assertion.job_workflow_sha && assertion.event_name == 'push' && assertion.ref == 'refs/heads/main' && assertion.environment == 'production'"
  production_publish_workflow_condition = "assertion.job_workflow_ref == 'collinbentley1/platform/.github/workflows/deploy-prod.yml@' + assertion.job_workflow_sha && assertion.event_name == 'push' && assertion.ref == 'refs/heads/main' && assertion.environment == 'production-publish'"
  terraform_workflow_condition          = "assertion.job_workflow_ref == 'collinbentley1/platform/.github/workflows/infrastructure.yml@' + assertion.job_workflow_sha && assertion.event_name == 'push' && assertion.ref == 'refs/heads/main' && assertion.environment == 'production'"

  # Compatibility accepts an immediately previous reviewed workflow ref for
  # each old operational identity, but maps a distinct attribute per path. A
  # token accepted for one legacy workflow therefore cannot impersonate a
  # different service account through an aggregate repository/environment key.
  legacy_preview_deploy_workflow_condition = "assertion.job_workflow_ref.startsWith('collinbentley1/platform/.github/workflows/deploy-preview.yml@') && assertion.event_name == 'pull_request' && assertion.actor != 'dependabot[bot]' && (!has(assertion.environment) || assertion.environment == 'preview-cloud')"
  legacy_preview_operator_workflow_condition = join(" || ", [
    "assertion.job_workflow_ref.startsWith('collinbentley1/platform/.github/workflows/deploy-preview.yml@') && assertion.event_name == 'pull_request' && assertion.actor != 'dependabot[bot]' && assertion.environment == 'preview-operations'",
    "assertion.job_workflow_ref.startsWith('collinbentley1/platform/.github/workflows/cleanup-preview.yml@') && assertion.event_name == 'pull_request' && (!has(assertion.environment) || assertion.environment == 'preview-operations')",
    "assertion.job_workflow_ref.startsWith('collinbentley1/platform/.github/workflows/reconcile-previews.yml@') && (assertion.event_name == 'schedule' || assertion.event_name == 'workflow_dispatch') && assertion.ref == 'refs/heads/main' && has(assertion.environment) && assertion.environment == 'preview-operations'",
  ])
  preview_operator_transition_workflow_sha_condition = length(var.preview_operator_transition_workflow_shas) == 0 ? "false" : join(" || ", [
    for sha in sort(tolist(var.preview_operator_transition_workflow_shas)) : "assertion.job_workflow_sha == '${sha}'"
  ])
  legacy_preview_operator_attribute_condition = "(${local.legacy_preview_operator_workflow_condition}) && (${local.preview_operator_transition_workflow_sha_condition})"
  legacy_prod_deploy_workflow_condition       = "assertion.job_workflow_ref.startsWith('collinbentley1/platform/.github/workflows/deploy-prod.yml@') && assertion.event_name == 'push' && assertion.ref == 'refs/heads/main' && assertion.environment == 'production'"
  legacy_terraform_workflow_condition         = "assertion.job_workflow_ref.startsWith('collinbentley1/platform/.github/workflows/infrastructure.yml@') && assertion.event_name == 'push' && assertion.ref == 'refs/heads/main' && assertion.environment == 'production'"
  legacy_workflow_condition = join(" || ", [
    "(${local.legacy_preview_deploy_workflow_condition})",
    "(${local.legacy_preview_operator_workflow_condition})",
    "(${local.legacy_prod_deploy_workflow_condition})",
    "(${local.legacy_terraform_workflow_condition})",
    # Phase A must accept the new base-controlled pull_request_target paths as
    # well as the immediately previous pull_request paths.
    "(${local.preview_deploy_workflow_condition})",
    "(${local.preview_operator_workflow_condition})",
    # Publisher identities never receive a generic compatibility binding. Even
    # in phase A, only a full-SHA caller can mint their exact mapped attribute.
    "(${local.preview_publish_workflow_condition})",
    "(${local.production_publish_workflow_condition})",
  ])
  trusted_workflow_sha_condition = join(" || ", [
    for sha in sort(tolist(var.trusted_platform_workflow_shas)) : "assertion.job_workflow_sha == '${sha}'"
  ])

  exact_workflow_provider_condition = join(" && ", [
    "assertion.repository_owner_id == '${var.github_owner_id}'",
    "assertion.repository_id == '${var.github_repository_id}'",
    "has(assertion.job_workflow_ref)",
    "has(assertion.job_workflow_sha)",
    "has(assertion.run_attempt)",
    "assertion.run_attempt == '1'",
    "assertion.runner_environment == 'github-hosted'",
    "(${local.trusted_workflow_sha_condition})",
    "((${local.preview_deploy_workflow_condition}) || (${local.preview_operator_workflow_condition}) || (${local.preview_publish_workflow_condition}) || (${local.production_workflow_condition}) || (${local.production_publish_workflow_condition}) || (${local.terraform_workflow_condition}))",
  ])
  legacy_provider_condition = "assertion.repository_owner_id == '${var.github_owner_id}' && assertion.repository_id == '${var.github_repository_id}' && has(assertion.job_workflow_ref) && has(assertion.job_workflow_sha) && has(assertion.run_attempt) && assertion.run_attempt == '1' && assertion.runner_environment == 'github-hosted' && (${local.trusted_workflow_sha_condition}) && (${local.legacy_workflow_condition})"
  provider_condition        = var.legacy_compatibility_mode ? local.legacy_provider_condition : local.exact_workflow_provider_condition

  github_attribute_mapping = {
    "attribute.preview_deploy_workflow_sha"   = "(${local.preview_deploy_workflow_condition}) ? assertion.job_workflow_sha : 'denied'"
    "attribute.preview_operator_workflow_sha" = "(${local.preview_operator_workflow_condition}) ? assertion.job_workflow_sha : 'denied'"
    "attribute.preview_publish_workflow_sha"  = "(${local.preview_publish_workflow_condition}) ? assertion.job_workflow_sha : 'denied'"
    "attribute.prod_workflow_sha"             = "(${local.production_workflow_condition}) ? assertion.job_workflow_sha : 'denied'"
    "attribute.prod_publish_workflow_sha"     = "(${local.production_publish_workflow_condition}) ? assertion.job_workflow_sha : 'denied'"
    "attribute.terraform_workflow_sha"        = "(${local.terraform_workflow_condition}) ? assertion.job_workflow_sha : 'denied'"
    "attribute.legacy_preview_deploy"         = "(${local.legacy_preview_deploy_workflow_condition}) ? assertion.repository_id : 'denied'"
    "attribute.legacy_preview_operator"       = "(${local.legacy_preview_operator_attribute_condition}) ? assertion.repository_id : 'denied'"
    "attribute.legacy_prod_deploy"            = "(${local.legacy_prod_deploy_workflow_condition}) ? assertion.repository_id : 'denied'"
    "attribute.legacy_terraform"              = "(${local.legacy_terraform_workflow_condition}) ? assertion.repository_id : 'denied'"
    "google.subject"                          = "assertion.repository_owner_id + ':' + assertion.repository_id + ':' + assertion.run_id"
  }

  labels = {
    app        = var.app
    managed-by = "terraform"
  }

  # Organization Policy Service is useful only when this module manages the
  # preventive policy. Remove a caller-supplied/default entry for standalone
  # projects, and add it authoritatively for an organization-backed project.
  effective_required_services = setunion(
    setsubtract(var.required_services, toset(["orgpolicy.googleapis.com"])),
    var.manage_automatic_default_service_account_grants_policy ? toset(["orgpolicy.googleapis.com"]) : toset([]),
  )

}

check "wif_expression_limits" {
  assert {
    condition     = length(local.provider_condition) <= 4096
    error_message = "The rendered workload identity provider condition exceeds Google's 4096-character limit."
  }

  assert {
    condition     = alltrue([for expression in values(local.github_attribute_mapping) : length(expression) <= 2048])
    error_message = "A rendered workload identity attribute mapping expression exceeds Google's 2048-character limit."
  }
}

resource "google_project_service" "required" {
  for_each = local.effective_required_services

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
    google_project_iam_binding.editor_absent,
    google_storage_bucket_iam_member.terraform_state_access_logs_writer,
  ]
}

resource "google_storage_bucket" "bootstrap_state" {
  name                        = var.bootstrap_state_bucket_name
  project                     = var.project_id
  location                    = var.state_bucket_location
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  logging {
    log_bucket        = google_storage_bucket.terraform_state_access_logs.name
    log_object_prefix = "bootstrap-state/"
  }

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
      num_newer_versions    = 50
      with_state            = "ARCHIVED"
    }
  }

  labels = merge(local.labels, { purpose = "privileged-bootstrap-state" })

  depends_on = [
    google_project_service.required,
    google_project_iam_binding.editor_absent,
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

  depends_on = [
    google_project_service.required,
    google_project_iam_binding.editor_absent,
  ]
}

locals {
  legacy_storage_roles = toset([
    "roles/storage.legacyBucketOwner",
    "roles/storage.legacyBucketReader",
    "roles/storage.legacyObjectOwner",
    "roles/storage.legacyObjectReader",
  ])
}

resource "google_storage_bucket_iam_binding" "terraform_state_no_legacy_access" {
  for_each = local.legacy_storage_roles

  bucket  = google_storage_bucket.terraform_state.name
  role    = each.value
  members = []
}

resource "google_storage_bucket_iam_binding" "bootstrap_state_no_legacy_access" {
  for_each = local.legacy_storage_roles

  bucket  = google_storage_bucket.bootstrap_state.name
  role    = each.value
  members = []
}

resource "google_storage_bucket_iam_binding" "terraform_state_logs_no_legacy_access" {
  for_each = local.legacy_storage_roles

  bucket  = google_storage_bucket.terraform_state_access_logs.name
  role    = each.value
  members = []
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

  # Numeric IDs survive renames. run_id makes the subject non-reusable across runs.
  attribute_mapping = local.github_attribute_mapping

  attribute_condition = local.provider_condition

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

resource "google_service_account" "prod_publisher" {
  project      = var.project_id
  account_id   = "gha-prod-publish"
  display_name = "GitHub Actions Production Publisher"
  description  = var.prod_publisher_service_account_description

  depends_on = [google_project_service.required]
}

resource "google_service_account" "preview_deploy" {
  project      = var.project_id
  account_id   = "gha-preview-deploy"
  display_name = "GitHub Actions Preview Deploy"
  description  = var.preview_deploy_service_account_description

  depends_on = [google_project_service.required]
}

resource "google_service_account" "preview_operator" {
  project      = var.project_id
  account_id   = "gha-preview-operator"
  display_name = "GitHub Actions Preview Operator"
  description  = var.preview_operator_service_account_description

  depends_on = [google_project_service.required]
}

resource "google_service_account" "preview_publisher" {
  project      = var.project_id
  account_id   = "gha-preview-publish"
  display_name = "GitHub Actions Preview Publisher"
  description  = var.preview_publisher_service_account_description

  depends_on = [google_project_service.required]
}

resource "google_service_account" "exact_wif_canary" {
  project      = var.project_id
  account_id   = "gha-wif-canary"
  display_name = "GitHub Actions Exact WIF Canary"
  description  = "No-role identity that proves exact reusable-workflow SHA trust before legacy WIF bindings are removed."

  depends_on = [google_project_service.required]
}

resource "google_project_iam_custom_role" "cloud_run_revision_deployer" {
  project     = var.project_id
  role_id     = "cloudRunRevisionDeployer"
  title       = "Cloud Run Revision Deployer"
  description = "Updates and observes pre-created Cloud Run services without create, delete, or IAM policy permissions."
  permissions = [
    "run.operations.get",
    "run.services.get",
    "run.services.update",
  ]

  depends_on = [google_project_service.required]
}

resource "google_project_iam_custom_role" "secret_version_metadata_reader" {
  project     = var.project_id
  role_id     = "secretVersionMetadataReader"
  title       = "Secret Version Metadata Reader"
  description = "Reads secret and version metadata without access to secret payloads."
  permissions = [
    "secretmanager.secrets.get",
    "secretmanager.versions.get",
    "secretmanager.versions.list",
  ]

  depends_on = [google_project_service.required]
}

resource "google_project_iam_custom_role" "preview_traffic_image_downloader" {
  project     = var.project_id
  role_id     = "previewTrafficImageDownloader"
  title       = "Legacy Preview Traffic Image Downloader"
  description = "Transition-only role definition retained until the retired preview operator repository binding converges away."
  permissions = [
    "artifactregistry.repositories.downloadArtifacts",
  ]

  depends_on = [google_project_service.required]
}

resource "google_project_iam_custom_role" "terraform_convergence_reader" {
  project     = var.project_id
  role_id     = "terraformConvergenceReader"
  title       = "Terraform Convergence Reader"
  description = "Reads only infrastructure metadata for the immutable production convergence plan; cannot mutate services or read application data."
  permissions = concat(
    [
      "artifactregistry.locations.get",
      "artifactregistry.locations.list",
      "artifactregistry.repositories.get",
      "artifactregistry.repositories.getIamPolicy",
      "artifactregistry.repositories.list",
      "artifactregistry.repositories.listEffectiveTags",
      "artifactregistry.repositories.listTagBindings",
      "resourcemanager.projects.get",
      "resourcemanager.projects.getIamPolicy",
      "run.locations.list",
      "run.operations.get",
      "run.operations.list",
      "run.services.get",
      "run.services.getIamPolicy",
      "run.services.list",
      "run.services.listEffectiveTags",
      "run.services.listTagBindings",
      "serviceusage.services.get",
      "serviceusage.services.list",
      "serviceusage.services.use",
    ],
    contains(var.required_services, "firestore.googleapis.com") ? [
      "datastore.databases.get",
      "datastore.databases.getMetadata",
      "datastore.databases.list",
    ] : [],
    contains(var.required_services, "secretmanager.googleapis.com") ? [
      "secretmanager.locations.get",
      "secretmanager.locations.list",
      "secretmanager.secrets.get",
      "secretmanager.secrets.getIamPolicy",
      "secretmanager.secrets.list",
      "secretmanager.secrets.listEffectiveTags",
      "secretmanager.secrets.listTagBindings",
    ] : [],
  )

  depends_on = [google_project_service.required]
}

resource "google_service_account" "runtime" {
  project      = var.project_id
  account_id   = "cloud-run-runtime"
  display_name = var.runtime_display_name
  description  = var.runtime_description

  depends_on = [google_project_service.required]
}

resource "google_service_account" "preview_runtime" {
  project      = var.project_id
  account_id   = "cloud-run-preview"
  display_name = var.preview_runtime_display_name
  description  = var.preview_runtime_description

  depends_on = [google_project_service.required]
}

resource "google_service_account" "bootstrap_runtime" {
  project      = var.project_id
  account_id   = "cloud-run-bootstrap"
  display_name = "Cloud Run Bootstrap Runtime"
  description  = "No-role identity used only by the digest-pinned bootstrap image before the first application deploy."

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "terraform_convergence_reader" {
  project = var.project_id
  role    = google_project_iam_custom_role.terraform_convergence_reader.name
  member  = "serviceAccount:${google_service_account.terraform.email}"
}

resource "google_project_iam_member" "runtime_project_roles" {
  for_each = var.runtime_project_roles

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

# This authoritative empty binding removes every direct project Editor grant at
# each protected convergence. Organization-backed deployments separately enable
# the preventive automatic-grant policy below. A standalone deployment cannot
# prevent an out-of-band regrant between applies, so it must inventory workloads
# and assert a live zero-Editor policy after every protected service/API change.
resource "google_project_iam_binding" "editor_absent" {
  #checkov:skip=CKV_GCP_49:An authoritative empty binding removes impersonation-capable basic-role members; it grants no principal access.
  #checkov:skip=CKV_GCP_117:An authoritative empty Editor binding removes the basic role and prevents drift; it grants no principal access.
  project = var.project_id
  role    = "roles/editor"
  members = []

  depends_on = [google_project_service.required]
}

resource "google_org_policy_policy" "disable_automatic_default_service_account_grants" {
  count = var.manage_automatic_default_service_account_grants_policy ? 1 : 0

  name   = "projects/${data.google_project.current.number}/policies/iam.automaticIamGrantsForDefaultServiceAccounts"
  parent = "projects/${data.google_project.current.number}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }

  deletion_policy = "PREVENT"
  depends_on      = [google_project_service.required]
}

moved {
  from = google_org_policy_policy.disable_automatic_default_service_account_grants
  to   = google_org_policy_policy.disable_automatic_default_service_account_grants[0]
}

resource "google_storage_bucket_iam_member" "terraform_state_reader" {
  bucket = google_storage_bucket.terraform_state.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.terraform.email}"
}

moved {
  from = google_storage_bucket_iam_member.terraform_state_admin
  to   = google_storage_bucket_iam_member.terraform_state_reader
}

resource "google_service_account_iam_member" "prod_deploy_uses_runtime" {
  service_account_id = google_service_account.runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.prod_deploy.email}"
}

resource "google_service_account_iam_member" "preview_deploy_uses_preview_runtime" {
  service_account_id = google_service_account.preview_runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.preview_deploy.email}"
}

# Preserve only the addresses of the constrained legacy Workload Identity User
# bindings while compatibility mode transitions them to count-based resources.
moved {
  from = google_service_account_iam_member.terraform_wif_prod_env
  to   = google_service_account_iam_member.terraform_wif_prod_env[0]
}

moved {
  from = google_service_account_iam_member.prod_deploy_wif_prod_env
  to   = google_service_account_iam_member.prod_deploy_wif_prod_env[0]
}

moved {
  from = google_service_account_iam_member.preview_deploy_wif_repo
  to   = google_service_account_iam_member.preview_deploy_wif_repo[0]
}

# Each service account trusts only its reviewed reusable workflow, exact platform
# commit, immutable caller repository IDs, and expected event/ref/environment.
resource "google_service_account_iam_member" "terraform_wif_workflow_sha" {
  for_each = var.trusted_platform_workflow_shas

  service_account_id = google_service_account.terraform.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.terraform_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "prod_deploy_wif_workflow_sha" {
  for_each = var.trusted_platform_workflow_shas

  service_account_id = google_service_account.prod_deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.prod_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "prod_publisher_wif_workflow_sha" {
  for_each = var.trusted_platform_workflow_shas

  service_account_id = google_service_account.prod_publisher.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.prod_publish_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "preview_deploy_wif_workflow_sha" {
  for_each = var.trusted_platform_workflow_shas

  service_account_id = google_service_account.preview_deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.preview_deploy_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "preview_deploy_wif_preview_operations_workflow_sha" {
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.preview_deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.preview_operator_workflow_sha/${each.value}"
}

# Keep the previous identity usable only for an explicitly declared transition
# SHA. The steady-state transition set is empty and this binding disappears.
resource "google_service_account_iam_member" "preview_operator_wif_workflow_sha" {
  for_each = var.preview_operator_transition_workflow_shas

  service_account_id = google_service_account.preview_operator.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.preview_operator_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "preview_publisher_wif_workflow_sha" {
  for_each = var.trusted_platform_workflow_shas

  service_account_id = google_service_account.preview_publisher.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.preview_publish_workflow_sha/${each.value}"
}

# The canary has no project permissions and no legacy WIF binding. A successful
# access-token exchange against it proves the exact workflow attribute path.
resource "google_service_account_iam_member" "canary_wif_terraform_workflow_sha" {
  for_each = var.trusted_platform_workflow_shas

  service_account_id = google_service_account.exact_wif_canary.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.terraform_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "canary_wif_prod_workflow_sha" {
  for_each = var.trusted_platform_workflow_shas

  service_account_id = google_service_account.exact_wif_canary.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.prod_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "canary_wif_prod_publish_workflow_sha" {
  for_each = var.trusted_platform_workflow_shas

  service_account_id = google_service_account.exact_wif_canary.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.prod_publish_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "canary_wif_preview_deploy_workflow_sha" {
  for_each = var.trusted_platform_workflow_shas

  service_account_id = google_service_account.exact_wif_canary.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.preview_deploy_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "canary_wif_preview_operator_workflow_sha" {
  for_each = var.trusted_platform_workflow_shas

  service_account_id = google_service_account.exact_wif_canary.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.preview_operator_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "canary_wif_preview_publish_workflow_sha" {
  for_each = var.trusted_platform_workflow_shas

  service_account_id = google_service_account.exact_wif_canary.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.preview_publish_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "terraform_wif_prod_env" {
  count = var.legacy_compatibility_mode ? 1 : 0

  service_account_id = google_service_account.terraform.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.legacy_terraform_principal_set
}

resource "google_service_account_iam_member" "prod_deploy_wif_prod_env" {
  count = var.legacy_compatibility_mode ? 1 : 0

  service_account_id = google_service_account.prod_deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.legacy_prod_deploy_principal_set
}

resource "google_service_account_iam_member" "preview_deploy_wif_repo" {
  count = var.legacy_compatibility_mode ? 1 : 0

  service_account_id = google_service_account.preview_deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.legacy_preview_deploy_principal_set
}

resource "google_service_account_iam_member" "preview_operator_wif_repo" {
  count = var.legacy_compatibility_mode ? 1 : 0

  service_account_id = google_service_account.preview_operator.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.legacy_preview_operator_principal_set
}
