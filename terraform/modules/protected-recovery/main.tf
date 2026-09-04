data "google_project" "current" {
  project_id = var.project_id
}

locals {
  # Fixed-resource coordinates of the broker and its consumers, read from the
  # same file the service and the invoke workflow read. Who may invoke, for
  # which consumer, in which direction, and which consumer accounts are
  # actuated all come from the canonical workflow-authority manifest below,
  # never from this module.
  authority = jsondecode(file("${path.module}/../../../protected-recovery/authority.json"))
  consumers = { for consumer in local.authority.consumers : consumer.repository => consumer }

  # The one inventory of federated authority, shared with terraform/modules/bootstrap
  # and tools/ci/workflow-authority.ts. This module binds only recovery-domain
  # entries -- one per consumer and effect direction, keyed "<consumer>/<intent>",
  # each naming its own direction-bound invoker -- and the consumer-domain
  # entries are bound by each consumer's bootstrap.
  workflow_authority = jsondecode(file("${path.module}/../bootstrap/workflow-authority.json"))
  recovery_entries   = { for entry in local.workflow_authority : "${entry.consumer}/${entry.intent}" => entry if entry.trustDomain == "recovery" }
  target_accounts    = sort(distinct(flatten([for entry in local.workflow_authority : entry.serviceAccounts if entry.trustDomain == "consumer" && entry.purpose == "gcp"])))
  # One credential per direction: "gha-quarantine-<consumer>" would exceed the
  # 30-character service account ID limit, so QUARANTINE is named "isolate".
  invoker_prefixes = { QUARANTINE = "gha-isolate-", RESTORE = "gha-restore-" }

  authority_delimiter    = ":"
  github_owner_id        = local.authority.githubOwnerId
  platform_repository    = local.authority.platformRepository
  platform_repository_id = local.authority.platformRepositoryId
  region                 = local.authority.broker.region
  service_name           = local.authority.broker.serviceName
  workload_identity_pool = "projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.platform.workload_identity_pool_id}"
  broker_url             = "https://${local.service_name}-${data.google_project.current.number}.${local.region}.run.app"
  broker_email           = "recovery-broker@${var.project_id}.iam.gserviceaccount.com"

  labels = {
    app        = "protected-recovery"
    managed-by = "terraform"
  }

  required_services = toset([
    "cloudresourcemanager.googleapis.com",
    "cloudscheduler.googleapis.com",
    "firestore.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "run.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
    "sts.googleapis.com",
  ])

  legacy_storage_roles = toset([
    "roles/storage.legacyBucketOwner",
    "roles/storage.legacyBucketReader",
    "roles/storage.legacyObjectOwner",
    "roles/storage.legacyObjectReader",
  ])

  # Every invoker grant is one exact direct-dispatch tuple of the platform
  # repository itself: the dispatch job is its own caller, so the composite is
  # its workflow_ref, its workflow_sha (the active SHA, plus the transition SHA
  # only while the entry is transition-eligible), its literal environment, and
  # its event. Direct jobs carry no job_workflow_* claim; see the provider.
  invoker_bindings = {
    for binding in flatten([
      for invoker, entry in local.recovery_entries : [
        for caller in entry.callers : [
          for event in caller.events : [
            for sha in compact([var.active_workflow_sha, entry.transitionEligible ? var.transition_workflow_sha : null]) : {
              invoker = invoker
              key     = "${invoker}/${entry.job}:${event}@${sha}"
              authority = join(local.authority_delimiter, [
                "${local.platform_repository}/${caller.workflow}@${caller.ref}",
                sha,
                entry.environment,
                event,
              ])
            }
          ]
        ]
      ]
      ]) : binding.key => merge(binding, {
      member = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.authority/${binding.authority}"
    })
  }

  # Broker authority over consumer accounts is enabled only by reviewed
  # evidence that this module verifies mechanically against this very
  # deployment (see variables.tf for the shape): the evidence must name this
  # plan's broker image digest and reviewed platform revision, every consumer
  # project must sit live under the evidenced organization, the Deny canary
  # must cover at least the permissions below and except the broker, and every
  # target's permanent unique ID must be recorded. Until then the module grants
  # nothing outside its project. Offline no such evidence exists and the
  # committed identities are null, so no offline input can produce a grant.
  authority_enabled = var.broker_authority_evidence != null
  broker_principal  = "principal://iam.googleapis.com/projects/-/serviceAccounts/${local.broker_email}"

  # The minimum IAM Deny coverage the approved brief requires before the broker
  # may hold authority, in deny-policy permission form: every other principal
  # excluded from protected Firestore, GCS, and target-policy mutations, and
  # broker impersonation, signing, key creation, deployment, WIF configuration,
  # and artifact publication protected. The live canary decides what Google
  # supports; unsupported coverage blocks activation rather than shrinking this set.
  required_deny_coverage = toset([
    "artifactregistry.googleapis.com/repositories.uploadArtifacts",
    "datastore.googleapis.com/entities.create",
    "datastore.googleapis.com/entities.delete",
    "datastore.googleapis.com/entities.update",
    "iam.googleapis.com/serviceAccountKeys.create",
    "iam.googleapis.com/serviceAccounts.actAs",
    "iam.googleapis.com/serviceAccounts.getAccessToken",
    "iam.googleapis.com/serviceAccounts.getOpenIdToken",
    "iam.googleapis.com/serviceAccounts.implicitDelegation",
    "iam.googleapis.com/serviceAccounts.setIamPolicy",
    "iam.googleapis.com/serviceAccounts.signBlob",
    "iam.googleapis.com/serviceAccounts.signJwt",
    "iam.googleapis.com/workloadIdentityPoolProviders.update",
    "iam.googleapis.com/workloadIdentityPools.update",
    "run.googleapis.com/services.setIamPolicy",
    "run.googleapis.com/services.update",
    "storage.googleapis.com/objects.create",
    "storage.googleapis.com/objects.delete",
    "storage.googleapis.com/objects.update",
  ])

  # Every (consumer, target account) pair with the permanent identity the
  # authority records for it. A grant addresses the account by that identity,
  # never by its reusable email, so a recreated account at the same address
  # can never receive the broker's authority.
  target_identities = {
    for pair in setproduct(keys(local.consumers), local.target_accounts) : "${pair[0]}/${pair[1]}" => {
      account   = pair[1]
      consumer  = local.consumers[pair[0]]
      unique_id = try(local.consumers[pair[0]].serviceAccountUniqueIds[pair[1]], null)
    }
  }
  unrecorded_identities = sort([for key, identity in local.target_identities : key if !can(regex("^[1-9][0-9]*$", identity.unique_id))])
  identities_recorded   = length(local.unrecorded_identities) == 0
  actuator_grants       = local.authority_enabled && local.identities_recorded ? local.target_identities : {}
}

resource "google_project_service" "required" {
  for_each = local.required_services

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_firestore_database" "ledger" {
  project                           = var.project_id
  name                              = local.authority.broker.firestoreDatabase
  location_id                       = local.region
  type                              = "FIRESTORE_NATIVE"
  concurrency_mode                  = "PESSIMISTIC"
  app_engine_integration_mode       = "DISABLED"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"
  delete_protection_state           = "DELETE_PROTECTION_ENABLED"
  deletion_policy                   = "ABANDON"

  depends_on = [google_project_service.required]
}

# Committed ledger state is projected here under deterministic names with
# ifGenerationMatch=0; the broker can create and read objects but never delete
# or overwrite them. The ledger is the audit record, so no billable log sink is
# attached to this bucket.
resource "google_storage_bucket" "evidence" {
  #checkov:skip=CKV_GCP_62:The Firestore ledger is the audit record of every projection; no new billable access-log sink is created for the evidence bucket.
  name                        = "${var.project_id}-protected-recovery-evidence"
  project                     = var.project_id
  location                    = upper(local.region)
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  labels = local.labels

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.required]
}

resource "google_storage_bucket_iam_binding" "evidence_no_legacy_access" {
  for_each = local.legacy_storage_roles

  bucket  = google_storage_bucket.evidence.name
  role    = each.value
  members = []
}

resource "google_service_account" "broker" {
  project      = var.project_id
  account_id   = "recovery-broker"
  display_name = "Protected Recovery Broker"
  description  = "Runs the protected-recovery service: transacts in the exact ledger database, projects immutable evidence, and compare-and-sets the exact managed members of consumer federated service accounts addressed by permanent identity."

  depends_on = [google_project_service.required]
}

resource "google_service_account" "reconciler" {
  project      = var.project_id
  account_id   = local.authority.broker.reconcilerServiceAccount
  display_name = "Protected Recovery Reconciler"
  description  = "Cloud Scheduler identity with run.invoker only; the broker lets it reconcile recorded operations and nothing else."

  depends_on = [google_project_service.required]
}

resource "google_service_account" "invoker" {
  for_each = local.recovery_entries

  project      = var.project_id
  account_id   = each.value.serviceAccounts[0]
  display_name = "Protected Recovery Invoker (${each.value.consumer} ${lower(each.value.intent)})"
  description  = "Purpose-level invoker for the ${each.value.consumer} ${each.value.intent} direction only: bound to the exact protected-recovery-invoke job tuple and holding run.invoker on the broker only."

  depends_on = [google_project_service.required]
}

resource "google_iam_workload_identity_pool" "platform" {
  project                   = var.project_id
  workload_identity_pool_id = local.authority.broker.workloadIdentityPoolId
  display_name              = "GitHub Actions"
  description               = "GitHub Actions OIDC identities of ${local.platform_repository} protected-recovery dispatches."

  depends_on = [google_project_service.required]
}

resource "google_iam_workload_identity_pool_provider" "platform" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.platform.workload_identity_pool_id
  workload_identity_pool_provider_id = local.authority.broker.workloadIdentityProviderId
  display_name                       = "GitHub"
  description                        = "OIDC provider restricted to ${local.platform_repository}."

  # The subject is byte-identical to the consumer pools: numeric owner and
  # repository IDs on GitHub-hosted runners. The authority composite is not:
  # the recovery jobs are direct workflow_dispatch jobs, and GitHub documents
  # job_workflow_ref and job_workflow_sha only for jobs that call a reusable
  # workflow, so this composite maps the direct-job claims workflow_ref and
  # workflow_sha with the environment and event. String tests cannot prove
  # claim presence: decoding a real token minted by a protected-recovery-invoke
  # dispatch, and matching it against one of these bindings through
  # google-github-actions/auth, is a mandatory activation prerequisite.
  attribute_mapping = {
    "google.subject"      = "assertion.repository_owner_id + ':' + assertion.repository_id + ':' + assertion.runner_environment + ':' + assertion.run_id"
    "attribute.authority" = "assertion.workflow_ref + '${local.authority_delimiter}' + assertion.workflow_sha + '${local.authority_delimiter}' + assertion.environment + '${local.authority_delimiter}' + assertion.event_name"
  }

  attribute_condition = "google.subject.startsWith('${local.github_owner_id}:${local.platform_repository_id}:github-hosted:')"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com/"
  }
}

resource "google_service_account_iam_member" "invoker_authority" {
  for_each = local.invoker_bindings

  service_account_id = google_service_account.invoker[each.value.invoker].name
  role               = "roles/iam.workloadIdentityUser"
  member             = each.value.member

  lifecycle {
    precondition {
      condition = alltrue([
        for entry in values(local.recovery_entries) : (
          entry.purpose == "recovery" &&
          contains(keys(local.invoker_prefixes), entry.intent) &&
          length(entry.serviceAccounts) == 1 &&
          entry.serviceAccounts[0] == "${lookup(local.invoker_prefixes, entry.intent, "")}${entry.consumer}" &&
          length(entry.callers) == 1 &&
          entry.callers[0].workflow == entry.workflow &&
          contains(keys(local.consumers), entry.consumer) &&
          !strcontains(join("", concat([local.platform_repository, entry.workflow, entry.job, entry.environment, entry.consumer, entry.intent], flatten([for caller in entry.callers : concat([caller.workflow, caller.ref], caller.events)]))), local.authority_delimiter)
        )
        ]) && length(local.recovery_entries) == 2 * length(local.consumers) && alltrue([
        for consumer in keys(local.consumers) : contains(keys(local.recovery_entries), "${consumer}/QUARANTINE") && contains(keys(local.recovery_entries), "${consumer}/RESTORE")
      ])
      error_message = "Every declared consumer must have exactly two recovery-domain entries, QUARANTINE bound to gha-isolate-<consumer> and RESTORE bound to gha-restore-<consumer>, each its own caller and carrying no reserved delimiter in any tuple value."
    }
  }
}

resource "google_cloud_run_v2_service" "broker" {
  project             = var.project_id
  name                = local.service_name
  location            = local.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = true
  labels              = local.labels

  template {
    service_account                  = google_service_account.broker.email
    timeout                          = "120s"
    max_instance_request_concurrency = 8

    scaling {
      min_instance_count = 0
      max_instance_count = var.max_instances
    }

    containers {
      image = var.broker_image

      env {
        name  = "BROKER_AUDIENCE"
        value = local.broker_url
      }
      env {
        name  = "EVIDENCE_BUCKET"
        value = google_storage_bucket.evidence.name
      }
      env {
        name  = "FIRESTORE_DATABASE_ID"
        value = google_firestore_database.ledger.name
      }
      env {
        name  = "FIRESTORE_PROJECT_ID"
        value = var.project_id
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_cloud_run_v2_service_iam_member" "invokers" {
  for_each = merge(
    { for invoker, account in google_service_account.invoker : invoker => account.email },
    { reconciler = google_service_account.reconciler.email },
  )

  project  = var.project_id
  location = local.region
  name     = google_cloud_run_v2_service.broker.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${each.value}"
}

resource "google_cloud_scheduler_job" "reconcile" {
  project          = var.project_id
  region           = local.region
  name             = "protected-recovery-reconcile"
  description      = "Reconciles recorded pending operations through the low-authority reconciler identity; the broker sweeps the complete reconcilable set across invocations."
  schedule         = "*/5 * * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "180s"

  http_target {
    http_method = "POST"
    uri         = "${local.broker_url}/v1/reconcile"
    body        = base64encode("{}")
    headers = {
      "Content-Type" = "application/json"
    }

    oidc_token {
      service_account_email = google_service_account.reconciler.email
      audience              = local.broker_url
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "broker_ledger" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.broker.email}"

  condition {
    title       = "exact_protected_recovery_database"
    description = "Restrict the broker's Firestore access to the one ledger database."
    expression  = "resource.name == \"projects/${var.project_id}/databases/${google_firestore_database.ledger.name}\""
  }
}

resource "google_storage_bucket_iam_member" "broker_evidence" {
  for_each = toset(["roles/storage.objectCreator", "roles/storage.objectViewer"])

  bucket = google_storage_bucket.evidence.name
  role   = each.value
  member = "serviceAccount:${google_service_account.broker.email}"
}

# Organization ancestry is verified live, per consumer project, against the
# evidenced organization, and only once evidence is supplied at all.
data "google_project" "consumer" {
  for_each = local.authority_enabled ? local.consumers : {}

  project_id = each.value.projectId

  lifecycle {
    postcondition {
      condition     = self.org_id == try(var.broker_authority_evidence.organization_id, null)
      error_message = "Consumer project ${each.value.projectId} is not parented directly by the evidenced organization; its live ancestry must match broker_authority_evidence.organization_id before the broker gains authority over its accounts."
    }
  }
}

# The only cross-project authority: read the identity, get, and compare-and-set
# the IAM allow policy of the exact federated consumer accounts, granted per
# permanent identity, only once the evidence above verifies.
resource "google_project_iam_custom_role" "actuator" {
  for_each = local.authority_enabled ? local.consumers : {}

  project     = each.value.projectId
  role_id     = "protectedRecoveryActuator"
  title       = "Protected Recovery Actuator"
  description = "Reads the identity and compare-and-sets the IAM allow policy of exact federated service accounts; no create, delete, key, token, or actAs permission."
  permissions = [
    "iam.serviceAccounts.get",
    "iam.serviceAccounts.getIamPolicy",
    "iam.serviceAccounts.setIamPolicy",
  ]

  lifecycle {
    precondition {
      condition     = local.identities_recorded
      error_message = "Every target's permanent unique ID must be recorded in protected-recovery/authority.json before the broker gains authority; unrecorded: ${join(", ", local.unrecorded_identities)}."
    }
  }
}

resource "google_service_account_iam_member" "actuator" {
  for_each = local.actuator_grants

  service_account_id = "projects/${each.value.consumer.projectId}/serviceAccounts/${each.value.unique_id}"
  role               = google_project_iam_custom_role.actuator[each.value.consumer.repository].name
  member             = "serviceAccount:${google_service_account.broker.email}"
}
