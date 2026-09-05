data "google_project" "current" {
  project_id = var.project_id
}

# The identity applying this configuration. It is the one principal excepted
# from the Deny rules that protect the broker's deployment, so the exception
# set the canary must have observed is bound to whoever actually applies,
# never to a name supplied in an input.
data "google_client_openid_userinfo" "deployer" {}

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
  recovery_entries   = { for entry in local.workflow_authority : "${entry.consumer}/${entry.intent}" => entry if entry.trustDomain == "recovery" && entry.purpose == "recovery" }
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
    "orgpolicy.googleapis.com",
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

  # Every (consumer, target account) pair with the permanent identity the
  # authority records for it. A grant is made to the account the current email
  # resolves to only after that live account's unique ID is verified to be the
  # recorded one (data.google_service_account.target), so a recreated account
  # at the same address can never receive the broker's authority.
  target_identities = {
    for pair in setproduct(keys(local.consumers), local.target_accounts) : "${pair[0]}/${pair[1]}" => {
      account   = pair[1]
      consumer  = local.consumers[pair[0]]
      email     = "${pair[1]}@${local.consumers[pair[0]].projectId}.iam.gserviceaccount.com"
      unique_id = try(local.consumers[pair[0]].serviceAccountUniqueIds[pair[1]], null)
    }
  }
  unrecorded_identities = sort([for key, identity in local.target_identities : key if !can(regex("^[1-9][0-9]*$", identity.unique_id))])
  identities_recorded   = length(local.unrecorded_identities) == 0
}

# Broker authority over consumer accounts is enabled only by evidence that this
# module verifies mechanically against authenticated, immutable records (see
# variables.tf for what the input names): the GitHub run record of the Deny
# canary, the GitHub artifact record, and the artifact's attested predicate
# from GitHub's attestation store, each read here and checked below. Every
# consumer project must sit live under the evidenced organization, every
# target's permanent unique ID must be recorded and resolve live, and until
# all of that verifies the module grants nothing outside its project. Offline
# no such records exist and the committed identities are null, so no offline
# input can produce a grant.
locals {
  evidence          = var.broker_authority_evidence
  authority_enabled = local.evidence != null
  broker_principal  = "principal://iam.googleapis.com/projects/-/serviceAccounts/${local.broker_email}"

  github_api     = "https://api.github.com/repos/${local.platform_repository}"
  github_headers = { Accept = "application/vnd.github+json", "X-GitHub-Api-Version" = "2022-11-28" }
  # The one workflow whose run may evidence the canary, the one artifact name
  # it uploads, and the predicate type and schema it attests.
  deny_canary_workflow       = ".github/workflows/protected-recovery-deny-canary.yml"
  deny_canary_artifact       = "deny-canary"
  deny_canary_predicate_type = "https://github.com/collinbentley1/platform/protected-recovery/deny-canary/v1"
  deny_canary_schema         = "protected-recovery/deny-canary/v1"
}

data "http" "canary_run" {
  count = local.authority_enabled ? 1 : 0

  url                = "${local.github_api}/actions/runs/${local.evidence.deny_canary.run_id}"
  request_headers    = local.github_headers
  request_timeout_ms = 15000
}

data "http" "canary_artifact" {
  count = local.authority_enabled ? 1 : 0

  url                = "${local.github_api}/actions/artifacts/${local.evidence.deny_canary.artifact_id}"
  request_headers    = local.github_headers
  request_timeout_ms = 15000
}

data "http" "canary_attestations" {
  count = local.authority_enabled ? 1 : 0

  url                = "${local.github_api}/attestations/sha256:${local.evidence.deny_canary.artifact_sha256}"
  request_headers    = local.github_headers
  request_timeout_ms = 15000
}

# The exact IAM Deny matrix the canary must have proven, in deny-policy
# permission form: every row is one attachment point, one permission, the
# denied principal set (every principal), and the exact exception set. The
# broker project protects the ledger, the evidence bucket, the broker's own
# credentials, its deployment, its federation, and its image; each consumer
# project protects every path that could recreate a target identity, re-grant
# its credentials, replace its federation, or bypass the broker as the one
# writer of target policies. Exceptions are derived from this deployment
# alone: the broker for what the broker does, the invoker pool for the
# invokers' own federation, the Scheduler service agent for the reconciler's
# ID token, and the identity applying this configuration for deployment. A
# canary against any other resource, principal set, or exception set cannot
# satisfy a row, and a required permission the canary reports unsupported
# blocks activation rather than shrinking this set. The matrix is exported
# (outputs.tf) for the canary to exercise, so it has one definition.
locals {
  all_principals     = "principalSet://goog/public:all"
  deployer_email     = data.google_client_openid_userinfo.deployer.email
  deployer_principal = endswith(local.deployer_email, ".gserviceaccount.com") ? "principal://iam.googleapis.com/projects/-/serviceAccounts/${local.deployer_email}" : "principal://goog/subject/${local.deployer_email}"
  invoker_pool       = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/*"
  scheduler_agent    = "principal://iam.googleapis.com/projects/-/serviceAccounts/service-${data.google_project.current.number}@gcp-sa-cloudscheduler.iam.gserviceaccount.com"
  broker_attachment  = "cloudresourcemanager.googleapis.com/projects/${var.project_id}"

  broker_deny_rules = [
    {
      exceptions  = [local.broker_principal]
      permissions = ["datastore.googleapis.com/entities.create", "datastore.googleapis.com/entities.delete", "datastore.googleapis.com/entities.update", "storage.googleapis.com/objects.create"]
    },
    {
      exceptions  = []
      permissions = ["iam.googleapis.com/serviceAccountKeys.create", "iam.googleapis.com/serviceAccounts.implicitDelegation", "iam.googleapis.com/serviceAccounts.signBlob", "iam.googleapis.com/serviceAccounts.signJwt", "storage.googleapis.com/objects.delete", "storage.googleapis.com/objects.update"]
    },
    {
      exceptions  = [local.invoker_pool]
      permissions = ["iam.googleapis.com/serviceAccounts.getAccessToken"]
    },
    {
      exceptions  = [local.scheduler_agent]
      permissions = ["iam.googleapis.com/serviceAccounts.getOpenIdToken"]
    },
    {
      exceptions = [local.deployer_principal]
      permissions = [
        "artifactregistry.googleapis.com/repositories.uploadArtifacts",
        "cloudresourcemanager.googleapis.com/projects.setIamPolicy",
        "iam.googleapis.com/serviceAccounts.actAs",
        "iam.googleapis.com/serviceAccounts.create",
        "iam.googleapis.com/serviceAccounts.delete",
        "iam.googleapis.com/serviceAccounts.disable",
        "iam.googleapis.com/serviceAccounts.enable",
        "iam.googleapis.com/serviceAccounts.setIamPolicy",
        "iam.googleapis.com/serviceAccounts.undelete",
        "iam.googleapis.com/workloadIdentityPoolProviders.create",
        "iam.googleapis.com/workloadIdentityPoolProviders.delete",
        "iam.googleapis.com/workloadIdentityPoolProviders.undelete",
        "iam.googleapis.com/workloadIdentityPoolProviders.update",
        "iam.googleapis.com/workloadIdentityPools.create",
        "iam.googleapis.com/workloadIdentityPools.delete",
        "iam.googleapis.com/workloadIdentityPools.undelete",
        "iam.googleapis.com/workloadIdentityPools.update",
        "run.googleapis.com/services.create",
        "run.googleapis.com/services.delete",
        "run.googleapis.com/services.setIamPolicy",
        "run.googleapis.com/services.update",
      ]
    },
  ]

  consumer_deny_rules = [
    {
      exceptions  = [local.broker_principal]
      permissions = ["iam.googleapis.com/serviceAccounts.setIamPolicy"]
    },
    {
      exceptions = []
      permissions = [
        "cloudresourcemanager.googleapis.com/projects.setIamPolicy",
        "iam.googleapis.com/serviceAccountKeys.create",
        "iam.googleapis.com/serviceAccounts.create",
        "iam.googleapis.com/serviceAccounts.delete",
        "iam.googleapis.com/serviceAccounts.disable",
        "iam.googleapis.com/serviceAccounts.enable",
        "iam.googleapis.com/serviceAccounts.undelete",
        "iam.googleapis.com/workloadIdentityPoolProviders.create",
        "iam.googleapis.com/workloadIdentityPoolProviders.delete",
        "iam.googleapis.com/workloadIdentityPoolProviders.undelete",
        "iam.googleapis.com/workloadIdentityPoolProviders.update",
        "iam.googleapis.com/workloadIdentityPools.create",
        "iam.googleapis.com/workloadIdentityPools.delete",
        "iam.googleapis.com/workloadIdentityPools.undelete",
        "iam.googleapis.com/workloadIdentityPools.update",
      ]
    },
  ]

  required_deny_rows = concat(
    flatten([for rule in local.broker_deny_rules : [for permission in rule.permissions : {
      attachment = local.broker_attachment
      denied     = [local.all_principals]
      exceptions = [for exception in rule.exceptions : tostring(exception)]
      permission = permission
    }]]),
    flatten([for consumer in values(local.consumers) : [for rule in local.consumer_deny_rules : [for permission in rule.permissions : {
      attachment = "cloudresourcemanager.googleapis.com/projects/${consumer.projectId}"
      denied     = [local.all_principals]
      exceptions = [for exception in rule.exceptions : tostring(exception)]
      permission = permission
    }]]]),
  )
  required_deny_matrix = { for row in local.required_deny_rows : "${row.attachment}|${row.permission}" => row }
}

# The evidence, decoded from the three authenticated records, and every check
# the gate makes on it. A check that cannot be evaluated is a failed check.
locals {
  canary_run          = try(jsondecode(one(data.http.canary_run).response_body), {})
  canary_artifact     = try(jsondecode(one(data.http.canary_artifact).response_body), {})
  canary_attestations = try(jsondecode(one(data.http.canary_attestations).response_body).attestations, [])
  canary_statements = [
    for attestation in local.canary_attestations : jsondecode(base64decode(attestation.bundle.dsseEnvelope.payload))
    if try(attestation.bundle.dsseEnvelope.payloadType, "") == "application/vnd.in-toto+json" && can(jsondecode(base64decode(attestation.bundle.dsseEnvelope.payload)))
  ]
  canary_matching  = [for statement in local.canary_statements : statement if try(statement.predicateType, "") == local.deny_canary_predicate_type]
  canary_statement = length(local.canary_matching) == 1 ? local.canary_matching[0] : null
  canary           = try(local.canary_statement.predicate, null)

  canary_rules = flatten([
    for policy in try(local.canary.policies, []) : [
      for rule in try(policy.rules, []) : {
        attachment  = try(tostring(policy.attachmentPoint), "")
        denied      = try([for principal in rule.deniedPrincipals : tostring(principal)], [])
        exceptions  = try([for principal in rule.exceptionPrincipals : tostring(principal)], [])
        permissions = try([for permission in rule.deniedPermissions : tostring(permission)], [])
        observed    = try([for observation in rule.canary : { outcome = tostring(observation.outcome), permission = tostring(observation.permission), principal = tostring(observation.principal) }], [])
      }
    ]
  ])

  # A row is satisfied only by a rule at exactly its attachment point, denying
  # exactly every principal, excepting exactly the row's exception set, that
  # lists the permission and was observed DENIED for it by a principal outside
  # the exception set.
  deny_row_satisfied = {
    for key, row in local.required_deny_matrix : key => anytrue([
      for rule in local.canary_rules :
      rule.attachment == row.attachment &&
      sort(distinct(rule.denied)) == sort(row.denied) &&
      sort(distinct(rule.exceptions)) == sort(row.exceptions) &&
      contains(rule.permissions, row.permission) &&
      anytrue([for observation in rule.observed : observation.permission == row.permission && observation.outcome == "DENIED" && !contains(row.exceptions, observation.principal)])
    ])
  }
  unsatisfied_deny_rows = sort([for key, satisfied in local.deny_row_satisfied : key if !satisfied])
  unsupported_required  = sort(setintersection(toset(try([for permission in local.canary.unsupported : tostring(permission)], [])), toset([for row in local.required_deny_rows : row.permission])))

  evidence_checks = local.authority_enabled ? {
    run_recorded      = try(one(data.http.canary_run).status_code, 0) == 200
    run_succeeded     = try(local.canary_run.status == "completed" && local.canary_run.conclusion == "success" && local.canary_run.run_attempt == 1, false)
    run_is_the_canary = try(local.canary_run.path == local.deny_canary_workflow && local.canary_run.event == "workflow_dispatch" && tostring(local.canary_run.repository.id) == local.platform_repository_id && tostring(local.canary_run.head_repository.id) == local.platform_repository_id, false)
    run_at_this_head  = try(local.canary_run.head_sha == var.active_workflow_sha, false)
    artifact_recorded = try(one(data.http.canary_artifact).status_code, 0) == 200
    artifact_of_run   = try(tostring(local.canary_artifact.workflow_run.id) == local.evidence.deny_canary.run_id && local.canary_artifact.workflow_run.head_sha == var.active_workflow_sha && local.canary_artifact.name == local.deny_canary_artifact && local.canary_artifact.expired == false, false)
    artifact_digest   = try(local.canary_artifact.digest == "sha256:${local.evidence.deny_canary.artifact_sha256}", false)
    attested_once     = try(one(data.http.canary_attestations).status_code, 0) == 200 && local.canary_statement != null
    attests_artifact  = try(length(local.canary_statement.subject) == 1 && local.canary_statement.subject[0].digest.sha256 == local.evidence.deny_canary.artifact_sha256, false)
    predicate_bound   = try(local.canary.schema == local.deny_canary_schema && tostring(local.canary.run.id) == local.evidence.deny_canary.run_id && local.canary.run.headSha == var.active_workflow_sha && local.canary.brokerImage == var.broker_image && local.canary.organization == "organizations/${local.evidence.organization_id}", false)
    coverage_complete = length(local.unsatisfied_deny_rows) == 0
    supported         = length(local.unsupported_required) == 0
  } : {}
  evidence_failures = sort([for name, passed in local.evidence_checks : name if !passed])
  evidence_verified = local.authority_enabled && length(local.evidence_failures) == 0
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
  description  = "Runs the protected-recovery service: transacts in the exact ledger database, projects immutable evidence, inventories consumer federated accounts' credential paths, and compare-and-sets their exact managed members by permanent identity."

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

# The live account each recorded permanent identity currently has: the grant
# below addresses the account by the email the provider requires, and this
# read refuses the plan unless that email resolves right now to exactly the
# reviewed unique ID. A deleted and recreated account at the same address has
# a different unique ID and is refused here; the broker refuses it again at
# runtime before every read and write.
data "google_service_account" "target" {
  for_each = local.authority_enabled && local.identities_recorded ? local.target_identities : {}

  account_id = each.value.email
  project    = each.value.consumer.projectId

  lifecycle {
    postcondition {
      condition     = self.unique_id == each.value.unique_id && self.email == each.value.email
      error_message = "The account at ${each.value.email} has unique ID ${self.unique_id}, not the reviewed permanent identity ${each.value.unique_id}; a recreated account at the same address receives no authority."
    }
  }
}

# The only cross-project authority: read the identity, keys, and allow policy
# of, and compare-and-set the allow policy of, the exact federated consumer
# accounts, granted per verified permanent identity, only once the evidence
# above verifies.
resource "google_project_iam_custom_role" "actuator" {
  for_each = local.authority_enabled ? local.consumers : {}

  project     = each.value.projectId
  role_id     = "protectedRecoveryActuator"
  title       = "Protected Recovery Actuator"
  description = "Reads the identity, keys, and allow policy of exact federated service accounts and compare-and-sets their allow policy; no create, delete, key, token, or actAs permission."
  permissions = [
    "iam.serviceAccountKeys.list",
    "iam.serviceAccounts.get",
    "iam.serviceAccounts.getIamPolicy",
    "iam.serviceAccounts.setIamPolicy",
  ]

  lifecycle {
    precondition {
      condition     = local.identities_recorded
      error_message = "Every target's permanent unique ID must be recorded in protected-recovery/authority.json before the broker gains authority; unrecorded: ${join(", ", local.unrecorded_identities)}."
    }

    precondition {
      condition     = local.evidence_verified
      error_message = "broker_authority_evidence does not verify against the GitHub run, artifact, and attestation records and this deployment's required Deny matrix: failed checks [${join(", ", local.evidence_failures)}]; unsatisfied Deny rows [${join(", ", local.unsatisfied_deny_rows)}]; required permissions the canary reports unsupported [${join(", ", local.unsupported_required)}]."
    }
  }
}

resource "google_service_account_iam_member" "actuator" {
  for_each = local.authority_enabled && local.identities_recorded ? local.target_identities : {}

  service_account_id = data.google_service_account.target[each.key].name
  role               = google_project_iam_custom_role.actuator[each.value.consumer.repository].name
  member             = "serviceAccount:${google_service_account.broker.email}"

  lifecycle {
    precondition {
      condition     = data.google_service_account.target[each.key].unique_id == each.value.unique_id
      error_message = "The grant for ${each.key} must address the account whose live unique ID is the reviewed ${each.value.unique_id}."
    }
  }
}

# Read-only inventory of every other credential path of the targets: the
# consumer project's allow policy and custom roles, its effective
# credential-lifetime-extension policy, and its Compute, Cloud Run, and
# Cloud Build attachments, plus the right to bill those reads to the consumer
# project so no attachment API needs enabling in the broker project.
resource "google_project_iam_custom_role" "inventory" {
  for_each = local.authority_enabled ? local.consumers : {}

  project     = each.value.projectId
  role_id     = "protectedRecoveryInventory"
  title       = "Protected Recovery Inventory"
  description = "Read-only inventory of the credential paths of federated service accounts: project allow policy, custom roles, effective org policy, and Compute, Cloud Run, and Cloud Build attachments."
  permissions = [
    "cloudbuild.builds.list",
    "compute.instanceTemplates.list",
    "compute.instances.list",
    "iam.roles.get",
    "orgpolicy.policy.get",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "run.jobs.list",
    "run.services.list",
    "serviceusage.services.use",
  ]
}

resource "google_project_iam_member" "broker_inventory" {
  for_each = local.authority_enabled ? local.consumers : {}

  project = each.value.projectId
  role    = google_project_iam_custom_role.inventory[each.key].name
  member  = "serviceAccount:${google_service_account.broker.email}"
}

# The same inventory above the projects: folder and organization allow
# policies and organization custom roles, read-only, at the evidenced
# organization.
resource "google_organization_iam_custom_role" "inventory" {
  count = local.authority_enabled ? 1 : 0

  org_id      = local.evidence.organization_id
  role_id     = "protectedRecoveryInventory"
  title       = "Protected Recovery Inventory"
  description = "Read-only inventory of inherited credential grants: folder and organization allow policies and organization custom roles."
  permissions = [
    "iam.roles.get",
    "resourcemanager.folders.get",
    "resourcemanager.folders.getIamPolicy",
    "resourcemanager.organizations.get",
    "resourcemanager.organizations.getIamPolicy",
  ]
}

resource "google_organization_iam_member" "broker_inventory" {
  count = local.authority_enabled ? 1 : 0

  org_id = local.evidence.organization_id
  role   = google_organization_iam_custom_role.inventory[0].name
  member = "serviceAccount:${google_service_account.broker.email}"
}
