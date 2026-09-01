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

  deployment_parity_transition_bucket = "${var.project_id}-deployment-parity-state"
  deployment_parity_transition_object = "deployment-parity-transition"

  # Every standalone project grants the same narrowly read-only custom role to
  # each repository-local auditor. A preview transaction can therefore prove
  # that none of the four preview runtime identities gained access in a sibling
  # project without giving the traffic committer any IAM-read capability.
  preview_iam_auditor_members = toset([
    "serviceAccount:gha-preview-operator@cdbentley.iam.gserviceaccount.com",
    "serviceAccount:gha-preview-operator@critical-history-16823277.iam.gserviceaccount.com",
    "serviceAccount:gha-preview-operator@medlock-1025243085.iam.gserviceaccount.com",
    "serviceAccount:gha-preview-operator@runsetta.iam.gserviceaccount.com",
  ])

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

# A separate, non-state bucket contains one pre-created metadata-only CAS
# marker. Preview admission and DHI epoch transitions update only this object's
# custom metadata with generation + metageneration preconditions. They cannot
# create, delete, list, or read any Terraform state object.
resource "google_storage_bucket" "deployment_parity_transition" {
  name                        = local.deployment_parity_transition_bucket
  project                     = var.project_id
  location                    = var.state_bucket_location
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  logging {
    log_bucket        = google_storage_bucket.terraform_state_access_logs.name
    log_object_prefix = "deployment-parity-transition/"
  }

  versioning {
    enabled = true
  }

  labels = local.labels

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    google_project_service.required,
    google_project_iam_binding.editor_absent,
    google_storage_bucket_iam_member.terraform_state_access_logs_writer,
  ]
}

resource "google_storage_bucket_object" "deployment_parity_transition" {
  name         = local.deployment_parity_transition_object
  bucket       = google_storage_bucket.deployment_parity_transition.name
  content      = "{\"version\":1}\n"
  content_type = "application/json"

  metadata = {
    version       = "1"
    repository-id = var.github_repository_id
    state         = "clear"
  }

  lifecycle {
    prevent_destroy = true
    # CI owns only this strongly consistent metadata map. Object bytes,
    # identity, bucket policy, and every other property remain Terraform-owned.
    ignore_changes = [metadata]
  }
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

resource "google_storage_bucket_iam_binding" "deployment_parity_transition_no_legacy_access" {
  for_each = local.legacy_storage_roles

  bucket  = google_storage_bucket.deployment_parity_transition.name
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

  # Desired state during a protected apply, so the apply itself cannot re-enable
  # federation that the bridge disabled a moment earlier. Google's contract for a
  # disabled pool is the strong one: it blocks token exchange AND blocks
  # already-issued tokens from reaching resources. The provider-level flag only
  # blocks new exchanges and lets live tokens through, which is why the pool is
  # what gets quarantined.
  disabled = var.federation_quarantined

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

resource "google_service_account" "preview_commit" {
  project      = var.project_id
  account_id   = "gha-preview-commit"
  display_name = "GitHub Actions Preview Transaction Committer"
  description  = "Commits only fully proven preview traffic and exposure transitions on the exact pre-created preview service; no runtime impersonation, secret, or artifact-write access."

  depends_on = [google_project_service.required]
}

resource "google_service_account" "preview_operator" {
  project      = var.project_id
  account_id   = "gha-preview-operator"
  display_name = "GitHub Actions Preview IAM Auditor"
  description  = "Migration-stable account ID repurposed as an exact-workflow, read-only cross-project preview runtime IAM auditor; it has no Cloud Run mutation grant."

  depends_on = [google_project_service.required]
}

resource "google_service_account" "preview_publisher" {
  project      = var.project_id
  account_id   = "gha-preview-publish"
  display_name = "GitHub Actions Preview Publisher"
  description  = var.preview_publisher_service_account_description

  depends_on = [google_project_service.required]
}

resource "google_service_account" "deployment_parity_reader" {
  project      = var.project_id
  account_id   = "gha-deploy-parity"
  display_name = "GitHub Actions Deployment Parity Reader"
  description  = "Reads only the exact production image plus production and preview Cloud Run metadata needed to enforce DHI parity in serialized deploy transitions."

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
  description = "Updates and observes pre-created Cloud Run services; no IAM-policy mutation, create, delete, list, or service-account impersonation."
  permissions = [
    "run.operations.get",
    "run.revisions.get",
    "run.services.get",
    "run.services.update",
  ]

  depends_on = [google_project_service.required]
}

# The routine Medlock deploy must preserve the Terraform-created public site
# key, but it must not trust a mutable Cloud Run environment value by itself.
# This one-permission role lets the deploy re-read that exact key's public
# policy. It grants no key listing, creation, update, deletion, legacy-secret
# retrieval, assessment creation, or account access.
resource "google_project_iam_custom_role" "waitlist_recaptcha_key_reader" {
  count = contains(var.required_services, "recaptchaenterprise.googleapis.com") ? 1 : 0

  project     = var.project_id
  role_id     = "waitlistRecaptchaKeyReader"
  title       = "Waitlist reCAPTCHA Key Reader"
  description = "Reads only public reCAPTCHA key metadata so a production deploy can preserve and verify the Terraform-created ownership key."
  permissions = [
    "recaptchaenterprise.keys.get",
  ]

  depends_on = [google_project_service.required]
}

resource "google_project_iam_custom_role" "preview_traffic_committer" {
  project     = var.project_id
  role_id     = "previewTrafficCommitter"
  title       = "Preview Traffic Committer"
  description = "Reads exact preview revisions and service IAM, then commits traffic plus exposure only on the exact preview service; no create, delete, list, runtime impersonation, secret, or artifact-write permission."
  permissions = [
    "run.operations.get",
    "run.revisions.get",
    "run.services.get",
    "run.services.getIamPolicy",
    "run.services.setIamPolicy",
    "run.services.update",
  ]

  depends_on = [google_project_service.required]
}

resource "google_project_iam_custom_role" "deployment_parity_transition_coordinator" {
  project     = var.project_id
  role_id     = "deploymentParityTransitionCoordinator"
  title       = "Deployment Parity Transition Coordinator"
  description = "Gets and conditionally updates only the pre-created deployment parity marker; no object create, delete, list, state-bucket, or data-plane permissions."
  permissions = [
    "storage.objects.get",
    "storage.objects.update",
  ]

  depends_on = [google_project_service.required]
}

resource "google_project_iam_custom_role" "preview_iam_auditor" {
  project     = var.project_id
  role_id     = "previewIamAuditor"
  title       = "Preview Runtime IAM Auditor"
  description = "Analyzes IAM for exact preview runtime identities and brackets direct project policies; no list, mutation, secret, data, or impersonation permissions."
  permissions = [
    "cloudasset.assets.analyzeIamPolicy",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "serviceusage.services.use",
  ]

  depends_on = [google_project_service.required]
}

resource "google_project_iam_custom_role" "deployment_parity_cloud_run_reader" {
  project     = var.project_id
  role_id     = "deploymentParityCloudRunReader"
  title       = "Deployment Parity Cloud Run Reader"
  description = "Gets only the exact production and preview Cloud Run service and revision resources used by the DHI parity gate."
  permissions = [
    "run.revisions.get",
    "run.services.get",
  ]

  depends_on = [google_project_service.required]
}

resource "google_project_iam_custom_role" "deployment_parity_image_downloader" {
  project     = var.project_id
  role_id     = "deploymentParityImageDownloader"
  title       = "Deployment Parity Image Downloader"
  description = "Downloads blobs only from the exact production image repository so preview admission can verify the live DHI lineage."
  permissions = [
    "artifactregistry.repositories.downloadArtifacts",
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
    var.manage_firestore_field_ttl ? [
      "datastore.indexes.get",
      "datastore.indexes.list",
    ] : [],
    contains(var.required_services, "identitytoolkit.googleapis.com") ? [
      "firebaseauth.configs.get",
    ] : [],
    contains(var.required_services, "recaptchaenterprise.googleapis.com") ? [
      "recaptchaenterprise.keys.get",
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

# The protected owner bridge uses this role only for an approved production
# apply and only through a time-bounded project binding to a random single-run
# executor. It intentionally contains control-plane permissions only: no
# Secret Manager payload access/version mutation, Firestore entity access, or
# Artifact Registry upload/download/file/version permissions are present.
resource "google_project_iam_custom_role" "protected_terraform_apply" {
  project     = var.project_id
  role_id     = "protectedTerraformApply"
  title       = "Protected Terraform Apply"
  description = "Manages the declared production control plane without application data or artifact content access."
  permissions = concat(
    [
      "artifactregistry.locations.get",
      "artifactregistry.locations.list",
      "artifactregistry.repositories.create",
      "artifactregistry.repositories.delete",
      "artifactregistry.repositories.get",
      "artifactregistry.repositories.getIamPolicy",
      "artifactregistry.repositories.list",
      "artifactregistry.repositories.listEffectiveTags",
      "artifactregistry.repositories.listTagBindings",
      "artifactregistry.repositories.setIamPolicy",
      "artifactregistry.repositories.update",
      "resourcemanager.projects.get",
      "resourcemanager.projects.getIamPolicy",
      "run.locations.list",
      "run.operations.get",
      "run.operations.list",
      "run.services.create",
      "run.services.delete",
      "run.services.get",
      "run.services.getIamPolicy",
      "run.services.list",
      "run.services.listEffectiveTags",
      "run.services.listTagBindings",
      "run.services.setIamPolicy",
      "run.services.update",
      "serviceusage.services.get",
      "serviceusage.services.list",
      "serviceusage.services.use",
    ],
    contains(var.required_services, "firestore.googleapis.com") ? [
      "datastore.databases.create",
      "datastore.databases.delete",
      "datastore.databases.get",
      "datastore.databases.getMetadata",
      "datastore.databases.list",
      "datastore.databases.update",
      "datastore.operations.get",
      "datastore.operations.list",
    ] : [],
    # Firestore TTL is a field-level policy, patched through
    # projects.databases.collectionGroups.fields.patch. Without these the apply
    # fails and `expiresAt` stays inert: written by the application and enforced
    # by nothing.
    #
    # Three permissions, not the five that exist. A field is never created or
    # deleted -- Terraform's destroy path is also a patch back to defaults -- so
    # datastore.indexes.create and .delete are not required.
    #
    # roles/datastore.indexAdmin is deliberately NOT used: its permission list
    # is datastore.schemas.*, which does not include datastore.indexes.update,
    # so it would grant a different surface and still not work.
    var.manage_firestore_field_ttl ? [
      "datastore.indexes.get",
      "datastore.indexes.list",
      "datastore.indexes.update",
    ] : [],
    # Identity Platform configuration only. Nothing here can read, create, or
    # delete an account, and configs.getSecret is excluded: the apply identity
    # writes the sign-in configuration, it never reads provider secrets.
    contains(var.required_services, "identitytoolkit.googleapis.com") ? [
      "firebaseauth.configs.create",
      "firebaseauth.configs.get",
      "firebaseauth.configs.update",
    ] : [],
    # A protected apply creates and updates the one reviewed public score key.
    # Delete is deliberately absent and the resource uses deletion_policy =
    # PREVENT. retrievelegacysecretkey is also absent: this design has no secret.
    contains(var.required_services, "recaptchaenterprise.googleapis.com") ? [
      "recaptchaenterprise.keys.create",
      "recaptchaenterprise.keys.get",
      "recaptchaenterprise.keys.update",
    ] : [],
    contains(var.required_services, "secretmanager.googleapis.com") ? [
      "secretmanager.locations.get",
      "secretmanager.locations.list",
      "secretmanager.secrets.create",
      "secretmanager.secrets.delete",
      "secretmanager.secrets.get",
      "secretmanager.secrets.getIamPolicy",
      "secretmanager.secrets.list",
      "secretmanager.secrets.listEffectiveTags",
      "secretmanager.secrets.listTagBindings",
      "secretmanager.secrets.setIamPolicy",
      "secretmanager.secrets.update",
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

resource "google_project_iam_member" "preview_iam_auditors" {
  for_each = local.preview_iam_auditor_members

  project = var.project_id
  role    = google_project_iam_custom_role.preview_iam_auditor.name
  member  = each.value
}

# The three permissions the waitlist ownership flow needs, and nothing else.
#
# The runtime sends an email-link sign-in challenge by calling
# projects.accounts:sendOobCode with its own identity. roles/firebaseauth.admin
# would also work and is refused: it carries users.create, users.delete,
# users.update, users.get, and configs.getSecret, so a compromised runtime could
# enumerate the account directory, take over accounts, or read provider secrets.
# Sending mail needs none of that. The same role can create a scored reCAPTCHA
# assessment, but cannot list, alter, or retrieve a key. serviceusage.services.use
# is present solely because the documented keyless OOB check names this project
# as its quota project with X-Goog-User-Project.
#
# Scoped to applications that actually declare Identity Platform, so no other
# project's runtime gains a Firebase Auth permission it never uses.
resource "google_project_iam_custom_role" "waitlist_challenge_sender" {
  count = contains(var.required_services, "identitytoolkit.googleapis.com") ? 1 : 0

  project     = var.project_id
  role_id     = "waitlistChallengeSender"
  title       = "Waitlist Ownership Runtime"
  description = "Sends ownership mail, checks reCAPTCHA, and consumes project quota without account or key administration."
  permissions = concat(
    [
      "firebaseauth.users.sendEmail",
      "serviceusage.services.use",
    ],
    contains(var.required_services, "recaptchaenterprise.googleapis.com") ? [
      "recaptchaenterprise.assessments.create",
    ] : [],
  )

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "runtime_waitlist_challenge_sender" {
  count = contains(var.required_services, "identitytoolkit.googleapis.com") ? 1 : 0

  project = var.project_id
  role    = google_project_iam_custom_role.waitlist_challenge_sender[0].name
  member  = "serviceAccount:${google_service_account.runtime.email}"
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

resource "google_storage_bucket_iam_member" "preview_commit_transition_coordinator" {
  bucket = google_storage_bucket.deployment_parity_transition.name
  role   = google_project_iam_custom_role.deployment_parity_transition_coordinator.name
  member = "serviceAccount:${google_service_account.preview_commit.email}"

  condition {
    title       = "exact_deployment_parity_transition_object"
    description = "Restrict the coordinator's get/update permissions to the one pre-created per-repository marker."
    expression  = "resource.name == 'projects/_/buckets/${google_storage_bucket.deployment_parity_transition.name}/objects/${google_storage_bucket_object.deployment_parity_transition.name}'"
  }
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

resource "google_project_iam_member" "prod_deploy_waitlist_recaptcha_key_reader" {
  count = contains(var.required_services, "recaptchaenterprise.googleapis.com") ? 1 : 0

  project = var.project_id
  role    = google_project_iam_custom_role.waitlist_recaptcha_key_reader[0].name
  member  = "serviceAccount:${google_service_account.prod_deploy.email}"
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
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.terraform.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.terraform_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "prod_deploy_wif_workflow_sha" {
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.prod_deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.prod_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "prod_publisher_wif_workflow_sha" {
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.prod_publisher.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.prod_publish_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "preview_deploy_wif_workflow_sha" {
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.preview_deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.preview_deploy_workflow_sha/${each.value}"
}

# The active production workflow may stage only the sanitized preview baseline
# through this existing preview deployer. A transition SHA has no binding, so a
# predecessor token cannot roll a completed DHI epoch backward.
resource "google_service_account_iam_member" "preview_deploy_wif_prod_workflow_sha" {
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.preview_deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.prod_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "preview_commit_wif_workflow_sha" {
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.preview_commit.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.preview_deploy_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "preview_commit_wif_preview_operations_workflow_sha" {
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.preview_commit.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.preview_operator_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "preview_commit_wif_prod_workflow_sha" {
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.preview_commit.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.prod_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "preview_iam_audit_wif_workflow_sha" {
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.preview_operator.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.preview_deploy_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "preview_iam_audit_wif_preview_operations_workflow_sha" {
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.preview_operator.name
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
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.preview_publisher.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.preview_publish_workflow_sha/${each.value}"
}

# This identity is deliberately read-only and has no legacy binding. Both
# deployment paths may mint it only through their exact workflow-SHA attribute:
# preview verifies the live production image, while production proves that all
# still-routable preview tags carry the same DHI lineage identifier.
resource "google_service_account_iam_member" "deployment_parity_wif_preview_workflow_sha" {
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.deployment_parity_reader.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.preview_deploy_workflow_sha/${each.value}"
}

resource "google_service_account_iam_member" "deployment_parity_wif_prod_workflow_sha" {
  for_each = var.preview_operations_active_workflow_shas

  service_account_id = google_service_account.deployment_parity_reader.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.prod_workflow_sha/${each.value}"
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
