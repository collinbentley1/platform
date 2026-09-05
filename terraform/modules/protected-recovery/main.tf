data "google_project" "current" {
  project_id = var.project_id
}

# The identity applying this configuration. It holds no standing exception:
# the Deny matrix's bootstrap form excepts exactly the principal the authority
# names (protected-recovery/authority.json, bootstrapPrincipal), and an apply
# under that form is refused unless the applying identity is that principal.
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
  # and tools/ci/workflow-authority.ts. This module binds the recovery-domain
  # entries: one invoker per consumer and effect direction, keyed
  # "<consumer>/<intent>", and the one Deny canary job. The consumer-domain
  # entries are bound by each consumer's bootstrap to the consumer's own
  # accounts; here the same entries, at the platform commits each consumer
  # records in protected-recovery/authority.json, bind the consumer's
  # canonical jobs to that consumer's member-delivery identity so each job
  # can deliver its own credential to the broker (POST /v1/members).
  workflow_authority = jsondecode(file("${path.module}/../bootstrap/workflow-authority.json"))
  recovery_entries   = { for entry in local.workflow_authority : "${entry.consumer}/${entry.intent}" => entry if entry.trustDomain == "recovery" && entry.purpose == "recovery" }
  deny_canary_entry  = one([for entry in local.workflow_authority : entry if entry.trustDomain == "recovery" && entry.purpose == "deny-canary"])
  consumer_entries   = [for entry in local.workflow_authority : entry if entry.trustDomain == "consumer" && entry.purpose == "gcp"]
  target_accounts    = sort(distinct(flatten([for entry in local.consumer_entries : entry.serviceAccounts])))
  # One credential per direction: "gha-quarantine-<consumer>" would exceed the
  # 30-character service account ID limit, so QUARANTINE is named "isolate".
  invoker_prefixes = { QUARANTINE = "gha-isolate-", RESTORE = "gha-restore-" }
  member_prefix    = "gha-member-"
  deny_canary_id   = "gha-deny-canary"

  authority_delimiter    = ":"
  github_owner           = local.authority.githubOwner
  github_owner_id        = local.authority.githubOwnerId
  platform_repository    = local.authority.platformRepository
  platform_repository_id = local.authority.platformRepositoryId
  region                 = local.authority.broker.region
  service_name           = local.authority.broker.serviceName
  workload_identity_pool = "projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.platform.workload_identity_pool_id}"
  broker_url             = "https://${local.service_name}-${data.google_project.current.number}.${local.region}.run.app"
  broker_email           = "recovery-broker@${var.project_id}.iam.gserviceaccount.com"

  # The offline root that bootstraps and maintains the deployment, and the
  # principals infrastructure maintenance excepts, both reviewed and committed
  # in the authority; null and empty until named.
  bootstrap_principal    = local.authority.bootstrapPrincipal
  maintenance_principals = local.authority.maintenancePrincipals
  organization_recorded  = local.authority.organizationId

  labels = {
    app        = "protected-recovery"
    managed-by = "terraform"
  }

  # Artifact Registry hosts the broker's own image repository, the resource
  # the deployment row artifactregistry.googleapis.com/repositories.uploadArtifacts
  # protects and the Deny canary exercises against a throwaway repository here.
  required_services = toset([
    "artifactregistry.googleapis.com",
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

  # The Deny canary's own exact tuple, at the active commit only: the one
  # principal that may exchange for the canary identity.
  canary_bindings = local.deny_canary_entry == null ? {} : {
    for binding in flatten([
      for caller in local.deny_canary_entry.callers : [
        for event in caller.events : {
          key = "${local.deny_canary_entry.job}:${event}@${var.active_workflow_sha}"
          authority = join(local.authority_delimiter, [
            "${local.platform_repository}/${caller.workflow}@${caller.ref}",
            var.active_workflow_sha,
            local.deny_canary_entry.environment,
            event,
          ])
        }
      ]
      ]) : binding.key => merge(binding, {
      member = "principalSet://iam.googleapis.com/${local.workload_identity_pool}/attribute.authority/${binding.authority}"
    })
  }

  # Every canonical consumer job -- exactly the managed members the broker
  # actuates, derived from the same entries and the commits each consumer
  # records -- bound through the member provider of this pool to that
  # consumer's member-delivery identity. The composite is the consumer
  # provider's five-claim tuple, so a job that is a managed member of a
  # consumer is, and only is, a deliverer for that consumer. Null consumer
  # commits bind nothing.
  member_bindings = {
    for binding in flatten([
      for consumer in values(local.consumers) : [
        for entry in local.consumer_entries : [
          for caller in entry.callers : [
            for event in caller.events : [
              for sha in compact([consumer.activeWorkflowSha, entry.transitionEligible ? consumer.transitionWorkflowSha : null]) : {
                consumer = consumer.repository
                key      = "${consumer.repository}/${trimprefix(entry.workflow, ".github/workflows/")}:${entry.job}/${trimprefix(caller.workflow, ".github/workflows/")}:${event}@${sha}"
                authority = join(local.authority_delimiter, [
                  "${local.github_owner}/${consumer.repository}/${caller.workflow}@${caller.ref}",
                  "${local.platform_repository}/${entry.workflow}@${sha}",
                  sha,
                  entry.environment,
                  event,
                ])
              }
            ]
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
# variables.tf for what the input names): two GitHub Actions runs of the Deny
# canary workflow -- the control phase, in which every exercised request
# succeeded with the canary principal excepted from every rule, and the deny
# phase, in which the very same requests were refused with an IAM permission
# denial under the exact rules -- each with its run record, its artifact
# record, its archive and raw digests, and its attestation verified
# cryptographically by gh attestation verify (tools/ci/protected-recovery-
# verify-canary.sh), whose signing certificate binds the predicate to the
# exact signer workflow, repository, ref, head commit, trigger, runner, and
# run invocation. The evidence is then bound to the current Deny state: the
# live deny policies at every attachment point -- the broker project, the
# organization, and every consumer project -- are read through a credential-
# free external reader (tools/ci/protected-recovery-deny-state.sh) at plan,
# and again at apply whenever this apply would change what the broker is
# granted, and must carry the required matrix in an accepted form. Every
# consumer project and the broker project must sit live under the evidenced
# organization, every target's permanent unique ID must be recorded and
# resolve live, and until all of that verifies the module grants nothing
# outside its project. Offline no such records exist and the committed
# identities are null, so no offline input can produce a grant.
#
# The matrix has one steady form and three exact, composable widenings (see
# protected-recovery/src/deny.ts, whose derivation the enabled-path harness
# proves equal to this one):
#
#   steady       the only state under which the broker exercises authority.
#   deployment   per consumer: its two deploy identities excepted from exactly
#                run.services.create|update and actAs. Its ordinary state, and
#                authority disabled for it; the broker admits a quarantine only
#                against a fresh steady read.
#   bootstrap    the bootstrap principal excepted on exactly the rows this
#                module's own apply mutates; authority disabled everywhere.
#   maintenance  the maintenance principals excepted on the consumer IAM,
#                federation, lifecycle, role, organization-policy, and API rows
#                under an open ticket; authority disabled everywhere. This
#                module refuses to plan under it.
#
# Activation sequence, from an empty broker project (exercised with mock
# providers by enabled/enabled.tftest.hcl.in, and live by the activation
# rehearsal): (1) apply with broker_authority_evidence = null, which creates
# the broker project alone -- service, ledger, bucket, pool, providers,
# invoker, member-delivery, and canary identities and their bindings -- and
# nothing in any consumer project; (2) the root installs the required Deny
# matrix (outputs required_deny_matrix and bootstrap_deny_matrix) at the
# broker project, the organization, and every consumer project in its
# bootstrap form, excepting the bootstrap principal on exactly the rows step
# (3) mutates; (3) run the Deny canary in its control phase with the canary
# principal excepted, then in its deny phase with the exact rules, and apply
# with both runs as evidence, which is refused unless the live Deny state
# carries the matrix in the bootstrap or steady form and every mutation this
# apply makes is one the bootstrap form permits the applying identity, and
# only then creates the inventory and actuator grants; (4) the root retires
# the bootstrap exception -- the broker itself refuses every quarantine until
# it reads the steady form live, so the exception expires before authority is
# usable, without another apply. A later change of the active commit or of
# the deployment invalidates the evidence and the next apply is refused until
# a new canary is attested; an apply with null evidence revokes the grants.
locals {
  evidence          = var.broker_authority_evidence
  authority_enabled = local.evidence != null
  broker_principal  = "principal://iam.googleapis.com/projects/-/serviceAccounts/${local.broker_email}"
  canary_principal  = "principal://iam.googleapis.com/projects/-/serviceAccounts/${local.deny_canary_id}@${var.project_id}.iam.gserviceaccount.com"

  # The one workflow whose runs may evidence the canary, the one artifact name
  # it uploads, and the predicate type and schema it attests.
  deny_canary_workflow       = ".github/workflows/protected-recovery-deny-canary.yml"
  deny_canary_artifact       = "deny-canary"
  deny_canary_predicate_type = "https://github.com/collinbentley1/platform/protected-recovery/deny-canary/v2"
  deny_canary_schema         = "protected-recovery/deny-canary/v2"
  deny_canary_signer         = "https://github.com/${local.platform_repository}/${local.deny_canary_workflow}@refs/heads/main"
  canary_phases              = { control = "control", deny = "deny" }
}

# The two canary runs, verified on the applying machine: the script fetches
# the run and artifact records through gh, downloads the artifact, computes
# the archive digest and the extracted raw digest, requires both to be the
# evidenced ones, runs gh attestation verify against the platform repository
# and the deny-canary signer workflow, and answers with the records, the
# digests, the verified certificate summary, and the statement. Nothing in
# the predicate is trusted before the certificate below is checked.
data "external" "canary_verification" {
  for_each = local.authority_enabled ? local.canary_phases : {}

  program = ["bash", "${path.module}/../../../tools/ci/protected-recovery-verify-canary.sh"]
  query = {
    archive_sha256  = each.key == "control" ? local.evidence.deny_control.archive_sha256 : local.evidence.deny_canary.archive_sha256
    artifact_id     = each.key == "control" ? local.evidence.deny_control.artifact_id : local.evidence.deny_canary.artifact_id
    artifact_name   = local.deny_canary_artifact
    artifact_sha256 = each.key == "control" ? local.evidence.deny_control.artifact_sha256 : local.evidence.deny_canary.artifact_sha256
    predicate_type  = local.deny_canary_predicate_type
    repository      = local.platform_repository
    run_id          = each.key == "control" ? local.evidence.deny_control.run_id : local.evidence.deny_canary.run_id
    signer_workflow = "${local.platform_repository}/${local.deny_canary_workflow}"
  }
}

# The apply-time fence. Whenever this apply would change what the broker is
# granted -- the evidence, the image, the active commit, the recorded
# identities, or the consumer set -- this resource is replaced, and every
# live Deny read that depends on it is deferred from plan to apply, so the
# preconditions on the grants below are judged against the policies that
# stand at the moment of the grant, not against a plan saved earlier. When
# nothing changes the reads happen at plan.
resource "terraform_data" "authority_gate" {
  count = local.authority_enabled ? 1 : 0

  triggers_replace = {
    fingerprint = sha256(jsonencode({
      active_workflow_sha     = var.active_workflow_sha
      broker_image            = var.broker_image
      consumers               = sort(keys(local.consumers))
      evidence                = local.evidence
      identities              = local.target_identities
      transition_workflow_sha = var.transition_workflow_sha
    }))
  }
}

# The live Deny state, read as the applying identity through an external
# reader that obtains its credential internally and returns only the typed
# policy projection: no bearer is interpolated into any configuration, so no
# bearer is written into state (tools/ci/protected-recovery-state-scan-test.sh
# proves it with a sentinel).
data "external" "deny_state" {
  for_each = local.authority_enabled ? local.deny_attachments : {}

  program = ["bash", "${path.module}/../../../tools/ci/protected-recovery-deny-state.sh"]
  query = {
    attachment = each.key
  }

  depends_on = [terraform_data.authority_gate]
}

# Whether each consumer project enables the two attachment APIs the Deny
# canary cannot reach through IAM when they are disabled: a Compute or Cloud
# Build row whose identical request answered SERVICE_DISABLED in both canary
# phases is accepted only beside this read proving the API disabled now, at
# plan and again at apply (locals unserviceable_row_satisfied). Read through
# the same credential-free reader pattern as the Deny state.
data "external" "service_state" {
  for_each = local.authority_enabled ? local.service_reads : {}

  program = ["bash", "${path.module}/../../../tools/ci/protected-recovery-service-state.sh"]
  query = {
    project = each.value.project
    service = each.value.service
  }

  depends_on = [terraform_data.authority_gate]
}

# The exact IAM Deny matrix the canary must have proven and the live state
# must carry, in deny-policy permission form: every row is one attachment
# point, one permission, the denied principal set (every principal, service
# agents included), and the exact exception set. The broker project protects
# the ledger, the evidence bucket, the broker's own credentials, its
# deployment, its federation, and its image; each consumer project protects
# every path that could recreate a target identity, re-grant its
# credentials, replace its federation, attach it to a workload, deploy it,
# disable the APIs the inventory reads, or bypass the broker as the one
# writer of target policies; the organization protects the definitions of
# every role and the organization policy that could stretch a token's
# lifetime. Exceptions are derived from this deployment alone: the broker
# for what the broker does; the exact recovery invoker tuples, member-
# delivery tuples, and canary tuple for their own federation; the Scheduler
# service agent for the reconciler's ID token; the bootstrap principal, the
# maintenance principals, and each consumer's deploy identities only in the
# forms named for them. A canary against any other resource, principal set,
# or exception set cannot satisfy a row, and a required permission the live
# state does not carry blocks activation rather than shrinking this set. The
# matrices are exported (outputs.tf) for the canary and the root, so each
# form has one definition.
locals {
  all_principals     = "principalSet://goog/public:all"
  deployer_email     = data.google_client_openid_userinfo.deployer.email
  deployer_principal = endswith(local.deployer_email, ".gserviceaccount.com") ? "principal://iam.googleapis.com/projects/-/serviceAccounts/${local.deployer_email}" : "principal://goog/subject/${local.deployer_email}"
  invoker_tuples     = sort([for binding in values(local.invoker_bindings) : binding.member])
  member_tuples      = sort([for binding in values(local.member_bindings) : binding.member])
  canary_tuples      = sort([for binding in values(local.canary_bindings) : binding.member])
  scheduler_agent    = "principal://iam.googleapis.com/projects/-/serviceAccounts/service-${data.google_project.current.number}@gcp-sa-cloudscheduler.iam.gserviceaccount.com"
  broker_attachment  = "cloudresourcemanager.googleapis.com/projects/${var.project_id}"
  # The organization attachment point, named by the evidence and required to
  # be the one the authority records.
  organization_attachment = local.authority_enabled ? "cloudresourcemanager.googleapis.com/organizations/${local.evidence.organization_id}" : "cloudresourcemanager.googleapis.com/organizations/unrecorded"
  consumer_attachments    = { for consumer in values(local.consumers) : consumer.repository => "cloudresourcemanager.googleapis.com/projects/${consumer.projectId}" }
  deny_attachments = merge(
    { (local.broker_attachment) = var.project_id },
    { (local.organization_attachment) = local.authority_enabled ? local.evidence.organization_id : "unrecorded" },
    { for repository, attachment in local.consumer_attachments : attachment => local.consumers[repository].projectId },
  )
  deploy_identities   = ["gha-preview-deploy", "gha-prod-deploy"]
  bootstrap_exception = local.bootstrap_principal == null ? [] : [local.bootstrap_principal]

  broker_ledger_permissions = ["datastore.googleapis.com/entities.create", "datastore.googleapis.com/entities.delete", "datastore.googleapis.com/entities.get", "datastore.googleapis.com/entities.list", "datastore.googleapis.com/entities.update", "storage.googleapis.com/objects.create"]
  broker_sealed_permissions = ["iam.googleapis.com/serviceAccountKeys.create", "iam.googleapis.com/serviceAccounts.implicitDelegation", "iam.googleapis.com/serviceAccounts.signBlob", "iam.googleapis.com/serviceAccounts.signJwt", "storage.googleapis.com/objects.delete", "storage.googleapis.com/objects.update"]
  broker_deployment_permissions = [
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
  consumer_key_permissions = ["iam.googleapis.com/serviceAccountKeys.create"]
  consumer_lifecycle_permissions = [
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
  # The Cloud Run deploy path of the platform's own canonical jobs.
  consumer_deploy_permissions = ["iam.googleapis.com/serviceAccounts.actAs", "run.googleapis.com/services.create", "run.googleapis.com/services.update"]
  # Every other path that attaches a workload or disables an inventory API.
  consumer_freeze_permissions = [
    "cloudbuild.googleapis.com/builds.create",
    "compute.googleapis.com/instanceTemplates.create",
    "compute.googleapis.com/instances.create",
    "compute.googleapis.com/instances.setServiceAccount",
    "run.googleapis.com/jobs.create",
    "run.googleapis.com/jobs.update",
    "run.googleapis.com/workerpools.create",
    "run.googleapis.com/workerpools.update",
  ]
  consumer_serviceusage_permissions = ["serviceusage.googleapis.com/services.disable"]
  organization_role_permissions     = ["iam.googleapis.com/roles.create", "iam.googleapis.com/roles.delete", "iam.googleapis.com/roles.undelete", "iam.googleapis.com/roles.update"]
  organization_bootstrap_roles      = ["iam.googleapis.com/roles.create", "iam.googleapis.com/roles.delete", "iam.googleapis.com/roles.update"]
  organization_policy_permissions   = ["orgpolicy.googleapis.com/policy.set"]

  # The four exported forms: no flag; the bootstrap principal; the maintenance
  # principals; every consumer in deployment form.
  forms = {
    steady      = { bootstrap = false, deployment = [], maintenance = false }
    bootstrap   = { bootstrap = true, deployment = [], maintenance = false }
    maintenance = { bootstrap = false, deployment = [], maintenance = true }
    deployment  = { bootstrap = false, deployment = sort(keys(local.consumers)), maintenance = false }
  }
  matrices = {
    for name, flags in local.forms : name => {
      for row in concat(
        [for permission in local.broker_ledger_permissions : { attachment = local.broker_attachment, permission = permission, exceptions = [local.broker_principal] }],
        [for permission in local.broker_sealed_permissions : { attachment = local.broker_attachment, permission = permission, exceptions = [] }],
        [{ attachment = local.broker_attachment, permission = "iam.googleapis.com/serviceAccounts.getAccessToken", exceptions = concat(local.invoker_tuples, local.canary_tuples) }],
        [{ attachment = local.broker_attachment, permission = "iam.googleapis.com/serviceAccounts.getOpenIdToken", exceptions = concat([local.scheduler_agent], local.invoker_tuples, local.member_tuples) }],
        [for permission in local.broker_deployment_permissions : { attachment = local.broker_attachment, permission = permission, exceptions = flags.bootstrap ? local.bootstrap_exception : [] }],
        flatten([for repository, attachment in local.consumer_attachments : concat(
          [{ attachment = attachment, permission = "iam.googleapis.com/serviceAccounts.setIamPolicy", exceptions = concat([local.broker_principal], flags.bootstrap ? local.bootstrap_exception : [], flags.maintenance ? local.maintenance_principals : []) }],
          [{ attachment = attachment, permission = "cloudresourcemanager.googleapis.com/projects.setIamPolicy", exceptions = concat(flags.bootstrap ? local.bootstrap_exception : [], flags.maintenance ? local.maintenance_principals : []) }],
          [for permission in local.consumer_key_permissions : { attachment = attachment, permission = permission, exceptions = [] }],
          [for permission in local.consumer_lifecycle_permissions : { attachment = attachment, permission = permission, exceptions = flags.maintenance ? local.maintenance_principals : [] }],
          [for permission in local.consumer_deploy_permissions : { attachment = attachment, permission = permission, exceptions = contains(flags.deployment, repository) ? [for identity in local.deploy_identities : "principal://iam.googleapis.com/projects/-/serviceAccounts/${identity}@${local.consumers[repository].projectId}.iam.gserviceaccount.com"] : [] }],
          [for permission in local.consumer_freeze_permissions : { attachment = attachment, permission = permission, exceptions = [] }],
          [for permission in local.consumer_serviceusage_permissions : { attachment = attachment, permission = permission, exceptions = flags.maintenance ? local.maintenance_principals : [] }],
        )]),
        [for permission in local.organization_role_permissions : { attachment = local.organization_attachment, permission = permission, exceptions = concat(contains(local.organization_bootstrap_roles, permission) && flags.bootstrap ? local.bootstrap_exception : [], flags.maintenance ? local.maintenance_principals : []) }],
        [for permission in local.organization_policy_permissions : { attachment = local.organization_attachment, permission = permission, exceptions = flags.maintenance ? local.maintenance_principals : [] }],
        ) : "${row.attachment}|${row.permission}" => {
        attachment = row.attachment
        denied     = [local.all_principals]
        exceptions = sort(distinct([for exception in row.exceptions : tostring(exception)]))
        permission = row.permission
      }
    }
  }
  required_deny_matrix = local.matrices.steady
  # The consumer deploy rows, judged per consumer in either of their two
  # states; every other row decides the overlay.
  deploy_rows = { for key, row in local.required_deny_matrix : key => row if contains(values(local.consumer_attachments), row.attachment) && contains(local.consumer_deploy_permissions, row.permission) }
  # The consumer attachment rows whose API the consumer projects need not
  # enable, each with the API a SERVICE_DISABLED answer must name. No other
  # row -- actAs included, which Cloud Scheduler exercises on its own -- may
  # rest on a disabled API: every other row is proven denied or blocks.
  unserviceable_permissions = {
    "cloudbuild.googleapis.com/builds.create"            = "cloudbuild.googleapis.com"
    "compute.googleapis.com/instanceTemplates.create"    = "compute.googleapis.com"
    "compute.googleapis.com/instances.create"            = "compute.googleapis.com"
    "compute.googleapis.com/instances.setServiceAccount" = "compute.googleapis.com"
  }
  service_reads = {
    for read in distinct([
      for key, row in local.required_deny_matrix : {
        project = local.deny_attachments[row.attachment]
        service = lookup(local.unserviceable_permissions, row.permission, "")
      }
      if contains(keys(local.unserviceable_permissions), row.permission) && contains(values(local.consumer_attachments), row.attachment)
    ]) : "${read.project}|${read.service}" => read
  }
}

# The evidence, decoded from the authenticated records and the verified
# attestations, the live Deny state, and every check the gate makes on them.
# A check that cannot be evaluated is a failed check.
locals {
  verifications = { for phase in keys(local.canary_phases) : phase => try(data.external.canary_verification[phase].result, {}) }
  verified      = { for phase, result in local.verifications : phase => try(result.verified, "false") == "true" }
  certificates  = { for phase, result in local.verifications : phase => local.verified[phase] ? try(jsondecode(result.certificate), {}) : {} }
  statements    = { for phase, result in local.verifications : phase => local.verified[phase] ? try(jsondecode(result.statement), null) : null }
  runs          = { for phase, result in local.verifications : phase => try(jsondecode(result.run), {}) }
  artifacts     = { for phase, result in local.verifications : phase => try(jsondecode(result.artifact), {}) }
  predicates    = { for phase, statement in local.statements : phase => try(statement.predicate, null) }
  reasons       = join("; ", [for phase, result in local.verifications : "${phase}: ${try(result.reason, "no verification result")}"])
  phase_evidence = {
    control = local.authority_enabled ? local.evidence.deny_control : null
    deny    = local.authority_enabled ? local.evidence.deny_canary : null
  }

  # The attested rules of each phase: attachment, denied and exception sets,
  # permissions, and every observation with its request and response.
  canary_rules = {
    for phase, predicate in local.predicates : phase => flatten([
      for policy in try(predicate.policies, []) : [
        for rule in try(policy.rules, []) : {
          attachment  = try(tostring(policy.attachmentPoint), "")
          denied      = try([for principal in rule.deniedPrincipals : tostring(principal)], [])
          exceptions  = try([for principal in rule.exceptionPrincipals : tostring(principal)], [])
          permissions = try([for permission in rule.deniedPermissions : tostring(permission)], [])
          observed = try([for observation in rule.canary : {
            outcome    = tostring(observation.outcome)
            permission = tostring(observation.permission)
            principal  = tostring(observation.principal)
            request    = "${tostring(observation.request.method)} ${tostring(observation.request.url)}"
            reason     = try(tostring(observation.response.reason), "")
            denied     = try(tostring(observation.response.permission), "")
            service    = try(tostring(observation.response.service), "")
          }], [])
        }
      ]
    ])
  }
  canary_policies = {
    for phase, predicate in local.predicates : phase => [for policy in try(predicate.policies, []) : { attachment = try(tostring(policy.attachmentPoint), ""), etag = try(tostring(policy.etag), ""), name = try(tostring(policy.name), "") }]
  }

  # The live Deny state: every policy listed at every attachment point, read
  # by name; a listing or policy that cannot be read makes the state unread.
  live_states = { for attachment, state in data.external.deny_state : attachment => try(jsondecode(state.result.policies), null) }
  live_read   = alltrue([for attachment, state in data.external.deny_state : try(state.result.status, "") == "200" && local.live_states[attachment] != null])
  live_rules = flatten([
    for attachment, policies in local.live_states : [
      for policy in coalesce(policies, []) : [
        for rule in try(policy.rules, []) : {
          attachment  = attachment
          condition   = try(rule.denialCondition, null)
          denied      = try([for principal in rule.deniedPrincipals : tostring(principal)], [])
          exceptions  = try([for principal in rule.exceptionPrincipals : tostring(principal)], [])
          excepted    = try([for permission in rule.exceptionPermissions : tostring(permission)], [])
          permissions = try([for permission in rule.deniedPermissions : tostring(permission)], [])
        }
      ]
    ]
  ])
  # Each live policy by name and etag: the identity the canary attested, which
  # any later change of the policy moves.
  live_policy_identities = { for attachment, policies in local.live_states : attachment => sort([for policy in coalesce(policies, []) : "${tostring(policy.name)}@${tostring(policy.etag)}"]) }

  # Row satisfaction by the live state, per form: a rule at exactly the row's
  # attachment point, unconditioned and without permission exceptions,
  # denying exactly every principal, excepting exactly the row's set, that
  # lists the permission.
  live_row_satisfied = {
    for form, matrix in local.matrices : form => {
      for key, row in matrix : key => anytrue([
        for rule in local.live_rules :
        rule.attachment == row.attachment &&
        rule.condition == null &&
        length(rule.excepted) == 0 &&
        sort(distinct(rule.denied)) == sort(row.denied) &&
        sort(distinct(rule.exceptions)) == sort(row.exceptions) &&
        contains(rule.permissions, row.permission)
      ])
    }
  }
  # The overlay the live state carries: the first of steady, bootstrap,
  # maintenance whose every non-deploy row is satisfied; deploy rows per
  # consumer in either state.
  live_overlay_candidates = [for form in ["steady", "bootstrap", "maintenance"] : form if alltrue([for key, satisfied in local.live_row_satisfied[form] : satisfied if !contains(keys(local.deploy_rows), key)])]
  live_overlay            = length(local.live_overlay_candidates) == 0 ? "drifted" : local.live_overlay_candidates[0]
  live_deploy_rows_ok     = alltrue([for key, row in local.deploy_rows : local.live_row_satisfied.steady[key] || local.live_row_satisfied.deployment[key]])
  live_unsatisfied_rows   = sort([for key, satisfied in local.live_row_satisfied.steady : key if !satisfied && !local.live_row_satisfied.bootstrap[key] && !(contains(keys(local.deploy_rows), key) && local.live_row_satisfied.deployment[key])])
  # Required permissions the live state does not deny at all: unsupported by
  # the API, or never installed.
  missing_live_permissions = sort(distinct([for key, row in local.required_deny_matrix : key if !anytrue([for rule in local.live_rules : rule.attachment == row.attachment && contains(rule.permissions, row.permission)])]))

  # Row satisfaction by the canary. The deny phase must carry a rule with
  # exactly the row's exception set (in the steady or bootstrap form, deploy
  # rows in either state) and an observation DENIED for the permission by
  # the canary principal with an IAM permission denial naming that
  # permission; the control phase must carry the same rule with the canary
  # principal added to its exceptions and an observation ALLOWED for the same
  # request. The pairing is what attributes the denial to the rule rather
  # than to a missing allow.
  canary_exceptions = {
    for form in ["steady", "bootstrap", "deployment"] : form => { for key, row in local.matrices[form] : key => sort(row.exceptions) }
  }
  deny_observation = {
    for key, row in local.required_deny_matrix : key => try(flatten([
      for form in ["steady", "bootstrap", "deployment"] : [
        for rule in local.canary_rules.deny : [
          for observation in rule.observed : observation
          if rule.attachment == row.attachment &&
          sort(distinct(rule.denied)) == sort(row.denied) &&
          sort(distinct(rule.exceptions)) == local.canary_exceptions[form][key] &&
          (form != "deployment" || contains(keys(local.deploy_rows), key)) &&
          contains(rule.permissions, row.permission) &&
          observation.permission == row.permission &&
          observation.outcome == "DENIED" &&
          observation.principal == local.canary_principal &&
          observation.reason == "IAM_PERMISSION_DENIED" &&
          observation.denied == row.permission
        ]
      ]
    ])[0], null)
  }
  control_observation = {
    for key, row in local.required_deny_matrix : key => try(flatten([
      for form in ["steady", "bootstrap", "deployment"] : [
        for rule in local.canary_rules.control : [
          for observation in rule.observed : observation
          if rule.attachment == row.attachment &&
          sort(distinct(rule.denied)) == sort(row.denied) &&
          sort(distinct(rule.exceptions)) == sort(distinct(concat(local.canary_exceptions[form][key], [local.canary_principal]))) &&
          (form != "deployment" || contains(keys(local.deploy_rows), key)) &&
          contains(rule.permissions, row.permission) &&
          observation.permission == row.permission &&
          observation.outcome == "ALLOWED" &&
          observation.principal == local.canary_principal
        ]
      ]
    ])[0], null)
  }
  deny_pair_satisfied = {
    for key, row in local.required_deny_matrix : key => (
      local.deny_observation[key] != null &&
      local.control_observation[key] != null &&
      try(local.deny_observation[key].request == local.control_observation[key].request, false)
    )
  }

  # A consumer attachment row the canary could not reach through IAM: the
  # identical request answered SERVICE_DISABLED naming the row's API in the
  # deny phase and in the control phase, and the live read says the API is
  # disabled in that project now. No attachment can be created through a
  # disabled API, the broker's inventory records every attachment API's
  # enablement in the hash of every gate, and every attachment path also
  # needs actAs, which is proven denied on its own.
  unserviceable_observation = {
    for key, row in local.required_deny_matrix : key => try(flatten([
      for form in ["steady", "bootstrap", "deployment"] : [
        for rule in local.canary_rules.deny : [
          for observation in rule.observed : observation
          if rule.attachment == row.attachment &&
          sort(distinct(rule.denied)) == sort(row.denied) &&
          sort(distinct(rule.exceptions)) == local.canary_exceptions[form][key] &&
          (form != "deployment" || contains(keys(local.deploy_rows), key)) &&
          contains(rule.permissions, row.permission) &&
          observation.permission == row.permission &&
          observation.outcome == "UNSERVICEABLE" &&
          observation.principal == local.canary_principal &&
          observation.reason == "SERVICE_DISABLED" &&
          observation.service == lookup(local.unserviceable_permissions, row.permission, "")
        ]
      ]
    ])[0], null)
  }
  control_unserviceable_observation = {
    for key, row in local.required_deny_matrix : key => try(flatten([
      for form in ["steady", "bootstrap", "deployment"] : [
        for rule in local.canary_rules.control : [
          for observation in rule.observed : observation
          if rule.attachment == row.attachment &&
          sort(distinct(rule.denied)) == sort(row.denied) &&
          sort(distinct(rule.exceptions)) == sort(distinct(concat(local.canary_exceptions[form][key], [local.canary_principal]))) &&
          (form != "deployment" || contains(keys(local.deploy_rows), key)) &&
          contains(rule.permissions, row.permission) &&
          observation.permission == row.permission &&
          observation.outcome == "UNSERVICEABLE" &&
          observation.principal == local.canary_principal &&
          observation.reason == "SERVICE_DISABLED" &&
          observation.service == lookup(local.unserviceable_permissions, row.permission, "")
        ]
      ]
    ])[0], null)
  }
  service_states = { for key, read in data.external.service_state : key => try(read.result.state, "") }
  unserviceable_row_satisfied = {
    for key, row in local.required_deny_matrix : key => (
      contains(keys(local.unserviceable_permissions), row.permission) &&
      contains(values(local.consumer_attachments), row.attachment) &&
      local.unserviceable_observation[key] != null &&
      local.control_unserviceable_observation[key] != null &&
      try(local.unserviceable_observation[key].request == local.control_unserviceable_observation[key].request, false) &&
      try(local.service_states["${local.deny_attachments[row.attachment]}|${local.unserviceable_permissions[row.permission]}"] == "DISABLED", false)
    )
  }
  deny_row_satisfied    = { for key, row in local.required_deny_matrix : key => local.deny_pair_satisfied[key] || local.unserviceable_row_satisfied[key] }
  unsatisfied_deny_rows = sort([for key, satisfied in local.deny_row_satisfied : key if !satisfied])
  # The rows that rest on a disabled API rather than on a proven denial, so
  # the evidence says so by name.
  unserviceable_rows = sort([for key, satisfied in local.unserviceable_row_satisfied : key if satisfied && !local.deny_pair_satisfied[key]])

  # The canary observed the policies that stand now: at every attachment
  # point the same policies by name and etag, so a policy changed since the
  # deny phase, however benignly, refuses the evidence until a new canary
  # attests the state that stands.
  live_matches_canary = (
    length(local.canary_policies.deny) > 0 &&
    alltrue([for attachment in keys(local.deny_attachments) : sort([for policy in local.canary_policies.deny : "${policy.name}@${policy.etag}" if policy.attachment == attachment]) == try(local.live_policy_identities[attachment], [])])
  )

  # The certificate binds each predicate to its producer: every value below is
  # set by GitHub's OIDC token at signing time and cannot be written by the
  # workflow.
  certificate_bound = {
    for phase, certificate in local.certificates : phase => try(
      certificate.issuer == "https://token.actions.githubusercontent.com" &&
      tostring(certificate.sourceRepositoryIdentifier) == local.platform_repository_id &&
      tostring(certificate.sourceRepositoryOwnerIdentifier) == local.github_owner_id &&
      certificate.sourceRepositoryURI == "https://github.com/${local.platform_repository}" &&
      certificate.sourceRepositoryRef == "refs/heads/main" &&
      certificate.sourceRepositoryDigest == var.active_workflow_sha &&
      certificate.buildSignerURI == local.deny_canary_signer &&
      certificate.buildTrigger == "workflow_dispatch" &&
      certificate.runnerEnvironment == "github-hosted" &&
      certificate.runInvocationURI == "https://github.com/${local.platform_repository}/actions/runs/${local.phase_evidence[phase].run_id}/attempts/1",
      false,
    )
  }

  phase_checks = local.authority_enabled ? merge([
    for phase in keys(local.canary_phases) : {
      "${phase}_run_recorded"         = try(local.verifications[phase].run_status, "") == "200"
      "${phase}_run_succeeded"        = try(local.runs[phase].status == "completed" && local.runs[phase].conclusion == "success" && local.runs[phase].run_attempt == 1, false)
      "${phase}_run_is_the_canary"    = try(local.runs[phase].path == local.deny_canary_workflow && local.runs[phase].event == "workflow_dispatch" && tostring(local.runs[phase].repository.id) == local.platform_repository_id && tostring(local.runs[phase].head_repository.id) == local.platform_repository_id, false)
      "${phase}_run_at_this_head"     = try(local.runs[phase].head_sha == var.active_workflow_sha, false)
      "${phase}_artifact_recorded"    = try(local.verifications[phase].artifact_status, "") == "200"
      "${phase}_artifact_of_run"      = try(tostring(local.artifacts[phase].workflow_run.id) == local.phase_evidence[phase].run_id && local.artifacts[phase].workflow_run.head_sha == var.active_workflow_sha && local.artifacts[phase].name == local.deny_canary_artifact && local.artifacts[phase].expired == false, false)
      "${phase}_archive_digest"       = try(local.artifacts[phase].digest == "sha256:${local.phase_evidence[phase].archive_sha256}" && local.verifications[phase].archive_sha256 == local.phase_evidence[phase].archive_sha256, false)
      "${phase}_raw_digest"           = try(local.verifications[phase].raw_sha256 == local.phase_evidence[phase].artifact_sha256 && local.phase_evidence[phase].artifact_sha256 != local.phase_evidence[phase].archive_sha256, false)
      "${phase}_attestation_verified" = local.verified[phase] && local.statements[phase] != null
      "${phase}_signer_is_the_canary" = local.certificate_bound[phase]
      "${phase}_attests_artifact"     = try(local.statements[phase].predicateType == local.deny_canary_predicate_type && length(local.statements[phase].subject) == 1 && local.statements[phase].subject[0].digest.sha256 == local.phase_evidence[phase].artifact_sha256, false)
      "${phase}_predicate_bound"      = try(local.predicates[phase].schema == local.deny_canary_schema && local.predicates[phase].phase == phase && tostring(local.predicates[phase].run.id) == local.phase_evidence[phase].run_id && local.predicates[phase].run.headSha == var.active_workflow_sha && local.predicates[phase].brokerImage == var.broker_image && local.predicates[phase].organization == "organizations/${local.evidence.organization_id}" && length(local.predicates[phase].unexercised) == 0, false)
    }
  ]...) : {}

  evidence_checks = local.authority_enabled ? merge(local.phase_checks, {
    control_before_deny    = try(tostring(local.predicates.deny.controlRunId) == local.evidence.deny_control.run_id && local.evidence.deny_control.run_id != local.evidence.deny_canary.run_id && timecmp(local.runs.control.updated_at, local.runs.deny.created_at) < 0, false)
    coverage_complete      = length(local.unsatisfied_deny_rows) == 0
    organization_recorded  = local.organization_recorded == local.evidence.organization_id
    broker_in_organization = tostring(data.google_project.current.org_id) == local.evidence.organization_id
    bootstrap_declared     = local.bootstrap_principal != null
    deny_state_read        = local.live_read && length(data.external.deny_state) == length(local.deny_attachments)
    services_read          = length(data.external.service_state) == length(local.service_reads) && alltrue([for key, read in data.external.service_state : try(read.result.status, "") == "200" && contains(["DISABLED", "ENABLED"], try(read.result.state, ""))])
    deny_state_current     = local.live_matches_canary
    deny_state_required    = contains(["steady", "bootstrap"], local.live_overlay) && local.live_deploy_rows_ok
    supported              = length(local.missing_live_permissions) == 0
    activation_permitted   = length(local.activation_blocked) == 0
    applying_identity      = local.live_overlay != "bootstrap" || local.deployer_principal == local.bootstrap_principal
  }) : {}
  evidence_failures = sort([for name, passed in local.evidence_checks : name if !passed])
  evidence_verified = local.authority_enabled && length(local.evidence_failures) == 0

  # Every mutation this module's own apply makes, as (attachment, permission,
  # principal); a row of the bootstrap form that denies one of them without
  # excepting its principal blocks activation. The sequence is provable, not
  # assumed: the grants of step 3 are exactly these, made by the bootstrap
  # principal.
  activation_mutations = concat(
    [
      for permission in [
        "cloudresourcemanager.googleapis.com/projects.setIamPolicy",
        "iam.googleapis.com/serviceAccounts.create",
        "iam.googleapis.com/serviceAccounts.setIamPolicy",
        "iam.googleapis.com/workloadIdentityPoolProviders.create",
        "iam.googleapis.com/workloadIdentityPoolProviders.update",
        "iam.googleapis.com/workloadIdentityPools.create",
        "iam.googleapis.com/workloadIdentityPools.update",
        "run.googleapis.com/services.create",
        "run.googleapis.com/services.setIamPolicy",
        "run.googleapis.com/services.update",
      ] : { attachment = local.broker_attachment, permission = permission, principal = coalesce(local.bootstrap_principal, "unrecorded") }
    ],
    flatten([
      for repository, attachment in local.consumer_attachments : [
        for permission in ["cloudresourcemanager.googleapis.com/projects.setIamPolicy", "iam.googleapis.com/serviceAccounts.setIamPolicy"] : {
          attachment = attachment
          permission = permission
          principal  = coalesce(local.bootstrap_principal, "unrecorded")
        }
      ]
    ]),
    [for permission in ["iam.googleapis.com/roles.create", "iam.googleapis.com/roles.delete", "iam.googleapis.com/roles.update"] : { attachment = local.organization_attachment, permission = permission, principal = coalesce(local.bootstrap_principal, "unrecorded") }],
    [for tuple in local.invoker_tuples : { attachment = local.broker_attachment, permission = "iam.googleapis.com/serviceAccounts.getOpenIdToken", principal = tuple }],
    [for tuple in local.invoker_tuples : { attachment = local.broker_attachment, permission = "iam.googleapis.com/serviceAccounts.getAccessToken", principal = tuple }],
    [for tuple in local.member_tuples : { attachment = local.broker_attachment, permission = "iam.googleapis.com/serviceAccounts.getOpenIdToken", principal = tuple }],
    [for tuple in local.canary_tuples : { attachment = local.broker_attachment, permission = "iam.googleapis.com/serviceAccounts.getAccessToken", principal = tuple }],
    [{ attachment = local.broker_attachment, permission = "iam.googleapis.com/serviceAccounts.getOpenIdToken", principal = local.scheduler_agent }],
    [{ attachment = local.broker_attachment, permission = "datastore.googleapis.com/entities.create", principal = local.broker_principal }],
    [{ attachment = local.broker_attachment, permission = "datastore.googleapis.com/entities.get", principal = local.broker_principal }],
    [{ attachment = local.broker_attachment, permission = "storage.googleapis.com/objects.create", principal = local.broker_principal }],
    [for repository, attachment in local.consumer_attachments : { attachment = attachment, permission = "iam.googleapis.com/serviceAccounts.setIamPolicy", principal = local.broker_principal }],
  )
  activation_blocked = sort(distinct([
    for mutation in local.activation_mutations : "${mutation.attachment}|${mutation.permission}|${mutation.principal}"
    if contains(keys(local.matrices.bootstrap), "${mutation.attachment}|${mutation.permission}") && !contains(local.matrices.bootstrap["${mutation.attachment}|${mutation.permission}"].exceptions, mutation.principal)
  ]))
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
  description  = "Runs the protected-recovery service: transacts in the exact ledger database, projects immutable evidence, inventories consumer credential paths and the live Deny state, and compare-and-sets exact managed members by permanent identity."

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

# One member-delivery identity per consumer: its canonical jobs impersonate
# it through the member provider to deliver their own credentials, and it
# holds run.invoker on the broker and nothing else.
resource "google_service_account" "member" {
  for_each = local.consumers

  project      = var.project_id
  account_id   = "${local.member_prefix}${each.key}"
  display_name = "Protected Recovery Member Delivery (${each.key})"
  description  = "Member-delivery identity for ${each.key}: reachable only by that consumer's canonical jobs, permitted only to deliver their credentials to the broker (POST /v1/members)."

  depends_on = [google_project_service.required]
}

# The Deny canary identity: bound to the canary job's exact tuple, granted
# nothing by this module. The root grants it the administrative allow roles
# it exercises immediately before a canary run and removes them after, and
# excepts it from every rule for the control phase alone.
resource "google_service_account" "deny_canary" {
  project      = var.project_id
  account_id   = local.deny_canary_id
  display_name = "Protected Recovery Deny Canary"
  description  = "Exercises the required Deny matrix from the deny-canary workflow in its control and deny phases; holds no standing authority from this module."

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

# The member provider: the consumers' canonical jobs, which call the platform
# reusable workflows, mapped exactly as each consumer's own provider maps
# them (the five-claim authority composite), admitted only from the declared
# consumer repositories on GitHub-hosted runners.
resource "google_iam_workload_identity_pool_provider" "members" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.platform.workload_identity_pool_id
  workload_identity_pool_provider_id = local.authority.broker.memberWorkloadIdentityProviderId
  display_name                       = "GitHub consumer jobs"
  description                        = "OIDC provider restricted to the canonical jobs of the declared consumer repositories, for member-credential delivery."

  attribute_mapping = {
    "google.subject"      = "assertion.repository_owner_id + ':' + assertion.repository_id + ':' + assertion.runner_environment + ':' + assertion.run_id"
    "attribute.authority" = "assertion.workflow_ref + '${local.authority_delimiter}' + assertion.job_workflow_ref + '${local.authority_delimiter}' + assertion.job_workflow_sha + '${local.authority_delimiter}' + assertion.environment + '${local.authority_delimiter}' + assertion.event_name"
  }

  attribute_condition = "google.subject.startsWith('${local.github_owner_id}:') && assertion.runner_environment == 'github-hosted' && assertion.repository_id in [${join(", ", [for consumer in values(local.consumers) : "'${consumer.repositoryId}'"])}]"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com/"
  }
}

resource "google_service_account_iam_member" "member_authority" {
  for_each = local.member_bindings

  service_account_id = google_service_account.member[each.value.consumer].name
  role               = "roles/iam.workloadIdentityUser"
  member             = each.value.member
}

resource "google_service_account_iam_member" "canary_authority" {
  for_each = local.canary_bindings

  service_account_id = google_service_account.deny_canary.name
  role               = "roles/iam.workloadIdentityUser"
  member             = each.value.member
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
    { for consumer, account in google_service_account.member : "member/${consumer}" => account.email },
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
      error_message = "broker_authority_evidence does not verify against the GitHub run and artifact records of both canary phases, their verified attestations and digests, the live Deny state, and this deployment's required Deny matrix: failed checks [${join(", ", local.evidence_failures)}]; attestation verification: ${local.reasons}; unsatisfied Deny rows [${join(", ", local.unsatisfied_deny_rows)}]; live overlay ${local.live_overlay}; live rows not as required [${join(", ", local.live_unsatisfied_rows)}]; required permissions the live state does not deny [${join(", ", local.missing_live_permissions)}]; mutations of this apply the bootstrap form would deny [${join(", ", local.activation_blocked)}]."
    }
  }

  depends_on = [terraform_data.authority_gate]
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
# consumer project's allow policy, custom roles, and organization policies,
# its Compute, Cloud Run, Cloud Build, and Cloud Scheduler attachments, plus
# the right to bill those reads to the consumer project so no attachment API
# needs enabling in the broker project.
resource "google_project_iam_custom_role" "inventory" {
  for_each = local.authority_enabled ? local.consumers : {}

  project     = each.value.projectId
  role_id     = "protectedRecoveryInventory"
  title       = "Protected Recovery Inventory"
  description = "Read-only inventory of the credential paths of federated service accounts: project allow policy, custom roles, organization policies, and Compute, Cloud Run, Cloud Build, and Cloud Scheduler attachments."
  permissions = [
    "cloudbuild.builds.list",
    "cloudscheduler.jobs.list",
    "cloudscheduler.locations.list",
    "compute.instanceTemplates.list",
    "compute.instances.list",
    "iam.roles.get",
    "orgpolicy.policy.get",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "run.executions.list",
    "run.jobs.list",
    "run.locations.list",
    "run.revisions.list",
    "run.services.list",
    "run.workerpools.list",
    "serviceusage.services.use",
  ]

  depends_on = [terraform_data.authority_gate]
}

resource "google_project_iam_member" "broker_inventory" {
  for_each = local.authority_enabled ? local.consumers : {}

  project = each.value.projectId
  role    = google_project_iam_custom_role.inventory[each.key].name
  member  = "serviceAccount:${google_service_account.broker.email}"
}

# The same inventory above the projects: folder and organization allow
# policies, organization custom roles, and the organization policies set at
# every ancestor, read-only, at the evidenced organization.
resource "google_organization_iam_custom_role" "inventory" {
  count = local.authority_enabled ? 1 : 0

  org_id      = local.evidence.organization_id
  role_id     = "protectedRecoveryInventory"
  title       = "Protected Recovery Inventory"
  description = "Read-only inventory of inherited credential grants: folder and organization allow policies, organization custom roles, and the organization policies set at every ancestor."
  permissions = [
    "iam.roles.get",
    "orgpolicy.policy.get",
    "resourcemanager.folders.get",
    "resourcemanager.folders.getIamPolicy",
    "resourcemanager.organizations.get",
    "resourcemanager.organizations.getIamPolicy",
  ]

  depends_on = [terraform_data.authority_gate]
}

resource "google_organization_iam_member" "broker_inventory" {
  count = local.authority_enabled ? 1 : 0

  org_id = local.evidence.organization_id
  role   = google_organization_iam_custom_role.inventory[0].name
  member = "serviceAccount:${google_service_account.broker.email}"
}

# The broker reads the live Deny policies at the broker project, the
# organization, and every consumer project before every quarantine is
# accepted, prepared, resumed, or restored: the runtime kill switch. Deny
# policies are readable through the predefined reviewer role alone.
resource "google_organization_iam_member" "broker_deny_reviewer" {
  count = local.authority_enabled ? 1 : 0

  org_id = local.evidence.organization_id
  role   = "roles/iam.denyReviewer"
  member = "serviceAccount:${google_service_account.broker.email}"
}
