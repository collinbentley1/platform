mock_provider "google" {}
mock_provider "http" {}
mock_provider "external" {}

override_data {
  target = data.google_project.current
  values = {
    number = "123456789012"
  }
}

override_data {
  target = data.google_client_openid_userinfo.deployer
  values = {
    email = "cloud-root@cdbentley.com"
  }
}

variables {
  project_id          = "recovery-test"
  broker_image        = "us-east4-docker.pkg.dev/recovery-test/broker/protected-recovery@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  active_workflow_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

# Every invoker grant is one exact direct-dispatch tuple of the platform repository:
#   <platform>/protected-recovery-invoke.yml@refs/heads/main:<sha>:recovery-<consumer>-<direction>:workflow_dispatch
# SHA "a" repeated forty times is the active SHA and "b" the transition SHA;
# "c" is a SHA no binding may ever name. The runs below pin the complete
# consumer -> direction -> invoker matrix, prove that neighbouring tuples bind
# nothing, that every invoker and member-delivery identity holds run.invoker
# only, that the broker is the only writer, that the activation sequence is
# permitted by the required Deny matrix, and that broker authority over
# consumer accounts is absent without evidence and unreachable while the
# committed target identities are null. The enabled path -- every identity
# recorded and verified, the Deny canary's attestation verified and bound to
# its signer, the live Deny state bound to the attested one -- is exercised
# by enabled/enabled.tftest.hcl.in through
# tools/ci/protected-recovery-enabled-test.sh against an isolated copy.
# These are mocked plan-shape tests over strings: they cannot prove which
# claims a real GitHub token carries. Decoding a real token from a
# protected-recovery-invoke dispatch and exchanging it through one of these
# bindings is a mandatory activation prerequisite.

run "provider_admits_only_github_hosted_jobs_of_the_platform_repository" {
  command = plan

  assert {
    condition     = google_iam_workload_identity_pool_provider.platform.attribute_condition == "google.subject.startsWith('16823277:1255856466:github-hosted:')"
    error_message = "The provider condition must be exactly the owner-ID, platform-repository-ID, and GitHub-hosted prefix of the mapped subject, so a consumer repository, a fork, or a self-hosted runner is refused."
  }

  assert {
    condition = google_iam_workload_identity_pool_provider.platform.attribute_mapping == tomap({
      "google.subject"      = "assertion.repository_owner_id + ':' + assertion.repository_id + ':' + assertion.runner_environment + ':' + assertion.run_id"
      "attribute.authority" = "assertion.workflow_ref + ':' + assertion.workflow_sha + ':' + assertion.environment + ':' + assertion.event_name"
    })
    error_message = "The subject must be byte-identical to the consumer pools, and the authority composite must map only the claims a direct workflow_dispatch job receives: workflow_ref, workflow_sha, environment, event_name."
  }

  assert {
    condition     = !strcontains(google_iam_workload_identity_pool_provider.platform.attribute_mapping["attribute.authority"], "job_workflow")
    error_message = "A direct dispatch job carries no job_workflow_ref or job_workflow_sha claim; the recovery composite must never reference one."
  }

  assert {
    condition     = google_iam_workload_identity_pool.platform.workload_identity_pool_id == "github-actions" && google_iam_workload_identity_pool_provider.platform.workload_identity_pool_provider_id == "github" && google_iam_workload_identity_pool_provider.platform.oidc[0].issuer_uri == "https://token.actions.githubusercontent.com/"
    error_message = "Exactly the reviewed pool, provider, and GitHub issuer must be declared."
  }
}

run "active_sha_binds_exactly_the_eight_direction_bound_recovery_tuples" {
  command = plan

  assert {
    condition = { for key, binding in google_service_account_iam_member.invoker_authority : key => binding.member } == merge([
      for consumer in ["cdbentley", "critical-history", "healthmcp", "runsetta"] : {
        "${consumer}/QUARANTINE/${consumer}-quarantine:workflow_dispatch@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" = "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/collinbentley1/platform/.github/workflows/protected-recovery-invoke.yml@refs/heads/main:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:recovery-${consumer}-quarantine:workflow_dispatch"
        "${consumer}/RESTORE/${consumer}-restore:workflow_dispatch@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"       = "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/collinbentley1/platform/.github/workflows/protected-recovery-invoke.yml@refs/heads/main:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:recovery-${consumer}-restore:workflow_dispatch"
      }
    ]...)
    error_message = "Active-only trust must bind exactly one workflow_dispatch tuple per consumer and direction, each to that direction's own invoker, and nothing else."
  }

  assert {
    condition = alltrue([
      for binding in values(google_service_account_iam_member.invoker_authority) :
      binding.role == "roles/iam.workloadIdentityUser" && !strcontains(binding.member, "*")
    ])
    error_message = "Every invoker binding must be a wildcard-free Workload Identity User grant."
  }

  assert {
    condition = { for invoker, account in google_service_account.invoker : invoker => account.account_id } == {
      "cdbentley/QUARANTINE"        = "gha-isolate-cdbentley"
      "cdbentley/RESTORE"           = "gha-restore-cdbentley"
      "critical-history/QUARANTINE" = "gha-isolate-critical-history"
      "critical-history/RESTORE"    = "gha-restore-critical-history"
      "healthmcp/QUARANTINE"        = "gha-isolate-healthmcp"
      "healthmcp/RESTORE"           = "gha-restore-healthmcp"
      "runsetta/QUARANTINE"         = "gha-isolate-runsetta"
      "runsetta/RESTORE"            = "gha-restore-runsetta"
    }
    error_message = "Exactly one purpose-level invoker per consumer and direction: gha-isolate-<consumer> for QUARANTINE and gha-restore-<consumer> for RESTORE; no credential may hold both directions."
  }

  assert {
    condition = alltrue([
      for key, binding in google_service_account_iam_member.invoker_authority :
      (startswith(key, "cdbentley/QUARANTINE/") ? strcontains(binding.member, ":recovery-cdbentley-quarantine:") : true) &&
      (startswith(key, "cdbentley/RESTORE/") ? strcontains(binding.member, ":recovery-cdbentley-restore:") : true)
    ])
    error_message = "The quarantine invoker may be reached only through the quarantine environment and the restore invoker only through the restore environment."
  }
}

run "transition_sha_extends_each_recovery_tuple_once" {
  command = plan

  variables {
    transition_workflow_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }

  assert {
    condition     = length(google_service_account_iam_member.invoker_authority) == 16 && length([for key in keys(google_service_account_iam_member.invoker_authority) : key if endswith(key, "@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]) == 8
    error_message = "A transition SHA must add one tuple beside each of the eight active tuples without altering them."
  }

  assert {
    condition = alltrue([
      for key, binding in google_service_account_iam_member.invoker_authority :
      strcontains(binding.member, "@refs/heads/main:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:recovery-") if endswith(key, "@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    ])
    error_message = "Every transition tuple must carry workflow_sha at the transition SHA."
  }
}

run "neighbouring_tuples_bind_nothing" {
  command = plan

  variables {
    transition_workflow_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }

  # caller repository, caller workflow, caller ref, workflow SHA, environment, event
  assert {
    condition = length([
      for pair in [
        ["collinbentley1/cdbentley", "protected-recovery-invoke.yml", "refs/heads/main", "a", "recovery-cdbentley-quarantine", "workflow_dispatch"],
        ["evil/platform", "protected-recovery-invoke.yml", "refs/heads/main", "a", "recovery-cdbentley-quarantine", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-bootstrap-implementation.yml", "refs/heads/main", "a", "recovery-cdbentley-quarantine", "workflow_dispatch"],
        ["collinbentley1/platform", "deploy-prod.yml", "refs/heads/main", "a", "recovery-cdbentley-quarantine", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/feature", "a", "recovery-cdbentley-quarantine", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "c", "recovery-cdbentley-quarantine", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "a", "recovery-cdbentley-restore", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "a", "recovery-cdbentley", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "a", "recovery-runsetta-quarantine", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "a", "production", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "a", "recovery-cdbentley-quarantine", "push"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "a", "recovery-cdbentley-quarantine", "pull_request_target"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "a", "supply-chain", "workflow_dispatch"],
      ] : pair
      if contains(
        [for key, binding in google_service_account_iam_member.invoker_authority : binding.member if startswith(key, "cdbentley/QUARANTINE/")],
        "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/${pair[0]}/.github/workflows/${pair[1]}@${pair[2]}:${join("", [for i in range(40) : pair[3]])}:${pair[4]}:${pair[5]}",
      )
    ]) == 0
    error_message = "A tuple that differs in caller repository, workflow, or branch; in workflow SHA; in environment -- including the same consumer's other direction; or in event must remain unbound, and one consumer's invoker must never accept another consumer's tuple."
  }

  assert {
    condition     = length([for binding in values(google_service_account_iam_member.invoker_authority) : binding.member if strcontains(binding.member, ":supply-chain:") || strcontains(binding.member, "/deploy-prod.yml@") || strcontains(binding.member, "/cdbentley/") || strcontains(binding.member, "job_workflow")]) == 0
    error_message = "No attestation, deploy, consumer-repository, or reusable-workflow tuple may reach a recovery invoker."
  }
}

run "invokers_hold_only_run_invoker_and_the_broker_is_the_only_writer" {
  command = plan

  assert {
    condition     = keys(google_cloud_run_v2_service_iam_member.invokers) == ["cdbentley/QUARANTINE", "cdbentley/RESTORE", "critical-history/QUARANTINE", "critical-history/RESTORE", "healthmcp/QUARANTINE", "healthmcp/RESTORE", "member/cdbentley", "member/critical-history", "member/healthmcp", "member/runsetta", "reconciler", "runsetta/QUARANTINE", "runsetta/RESTORE"] && alltrue([for grant in values(google_cloud_run_v2_service_iam_member.invokers) : grant.role == "roles/run.invoker"])
    error_message = "Exactly the eight direction-bound invokers, the four member-delivery identities, and the reconciler hold run.invoker on the broker, and nothing else."
  }

  assert {
    condition     = { for consumer, account in google_service_account.member : consumer => account.account_id } == { cdbentley = "gha-member-cdbentley", critical-history = "gha-member-critical-history", healthmcp = "gha-member-healthmcp", runsetta = "gha-member-runsetta" } && google_service_account.deny_canary.account_id == "gha-deny-canary"
    error_message = "One member-delivery identity per consumer and one Deny canary identity, named exactly."
  }

  assert {
    condition     = length(google_service_account_iam_member.member_authority) == 0 && keys(google_service_account_iam_member.canary_authority) == ["exercise:workflow_dispatch@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] && google_service_account_iam_member.canary_authority["exercise:workflow_dispatch@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"].member == "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/collinbentley1/platform/.github/workflows/protected-recovery-deny-canary.yml@refs/heads/main:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:protected-recovery-deny-canary:workflow_dispatch"
    error_message = "With no consumer commit recorded no canonical job is bound to a member-delivery identity, and the Deny canary identity is bound to exactly its own direct-dispatch tuple at the active commit."
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.members.workload_identity_pool_provider_id == "github-members" && google_iam_workload_identity_pool_provider.members.attribute_condition == "google.subject.startsWith('16823277:') && assertion.runner_environment == 'github-hosted' && assertion.repository_id in ['1255553151', '280932482', '1025243085', '711292980']" && strcontains(google_iam_workload_identity_pool_provider.members.attribute_mapping["attribute.authority"], "assertion.job_workflow_ref")
    error_message = "The member provider admits only the declared consumer repositories on GitHub-hosted runners and maps the consumers' five-claim authority composite."
  }

  assert {
    condition     = google_project_iam_member.broker_ledger.role == "roles/datastore.user" && google_project_iam_member.broker_ledger.condition[0].expression == "resource.name == \"projects/recovery-test/databases/protected-recovery\""
    error_message = "The broker's only project role is datastore.user on the exact ledger database."
  }

  assert {
    condition     = keys(google_storage_bucket_iam_member.broker_evidence) == ["roles/storage.objectCreator", "roles/storage.objectViewer"] && length([for role in local.legacy_storage_roles : role if length(google_storage_bucket_iam_binding.evidence_no_legacy_access[role].members) > 0]) == 0
    error_message = "The broker may create and read evidence objects only; no delete, overwrite, or legacy access exists."
  }

  assert {
    condition = length([
      for role in concat(
        [for grant in values(google_service_account_iam_member.invoker_authority) : grant.role],
        [for grant in values(google_service_account_iam_member.member_authority) : grant.role],
        [for grant in values(google_service_account_iam_member.canary_authority) : grant.role],
        [for grant in values(google_cloud_run_v2_service_iam_member.invokers) : grant.role],
        [for grant in values(google_storage_bucket_iam_member.broker_evidence) : grant.role],
        [for grant in values(google_project_iam_member.broker_inventory) : grant.role],
        [for grant in google_organization_iam_member.broker_inventory : grant.role],
        [google_project_iam_member.broker_ledger.role],
      ) : role
      if contains(["roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountKeyAdmin", "roles/iam.serviceAccountAdmin", "roles/iam.workloadIdentityPoolAdmin", "roles/iam.securityReviewer", "roles/owner", "roles/editor", "roles/viewer", "roles/datastore.owner", "roles/storage.admin", "roles/run.admin"], role)
    ]) == 0
    error_message = "No grant may create tokens or keys, administer service accounts or pools, or hold a basic, admin, or broad reviewer role."
  }

  assert {
    condition     = google_cloud_run_v2_service.broker.template[0].scaling[0].min_instance_count == 0 && google_cloud_run_v2_service.broker.template[0].scaling[0].max_instance_count == 2 && google_cloud_run_v2_service.broker.deletion_protection == true && google_cloud_run_v2_service.broker.template[0].containers[0].image == var.broker_image
    error_message = "The broker must scale from zero to a conservative ceiling, be protected from deletion, and run the digest-pinned image."
  }

  assert {
    condition     = google_cloud_scheduler_job.reconcile.http_target[0].uri == "https://protected-recovery-123456789012.us-east4.run.app/v1/reconcile" && google_cloud_scheduler_job.reconcile.http_target[0].oidc_token[0].audience == "https://protected-recovery-123456789012.us-east4.run.app"
    error_message = "The scheduler must call exactly the fleet-wide reconcile route with an ID token for the broker audience."
  }

  assert {
    condition     = { for env in google_cloud_run_v2_service.broker.template[0].containers[0].env : env.name => env.value if env.name != "EVIDENCE_BUCKET" && env.name != "FIRESTORE_DATABASE_ID" } == { BROKER_AUDIENCE = "https://protected-recovery-123456789012.us-east4.run.app", FIRESTORE_PROJECT_ID = "recovery-test" }
    error_message = "The broker must receive exactly its audience and ledger coordinates."
  }

  assert {
    condition     = !contains(local.required_services, "compute.googleapis.com") && !contains(local.required_services, "cloudbuild.googleapis.com")
    error_message = "Attachment inventories are billed to the consumer projects; the broker project must not enable Compute or Cloud Build and their default service accounts."
  }
}

run "broker_authority_over_consumer_accounts_is_absent_without_evidence" {
  command = plan

  assert {
    condition     = length(google_project_iam_custom_role.actuator) == 0 && length(google_service_account_iam_member.actuator) == 0 && length(data.google_service_account.target) == 0 && length(data.google_project.consumer) == 0
    error_message = "Without evidence the module must grant the broker nothing in any consumer project and must not even read the consumer projects or their accounts."
  }

  assert {
    condition     = length(google_project_iam_custom_role.inventory) == 0 && length(google_project_iam_member.broker_inventory) == 0 && length(google_organization_iam_custom_role.inventory) == 0 && length(google_organization_iam_member.broker_inventory) == 0 && length(data.http.canary_run) == 0 && length(data.http.canary_artifact) == 0 && length(data.external.canary_verification) == 0 && length(data.http.deny_policies) == 0 && length(data.http.deny_policy) == 0
    error_message = "Without evidence no inventory role exists anywhere, no GitHub record is read, no attestation is verified, and no live Deny policy is read."
  }

  assert {
    condition     = length(local.unrecorded_identities) == 36 && !local.identities_recorded
    error_message = "The committed authority records no target identity; all thirty-six (consumer, account) identities must be unrecorded until a reviewed change records the real ones."
  }
}

# The exact Deny matrix this deployment requires, derived from its own
# coordinates: every permission the approved brief names, at the broker
# project and at every consumer project, each with its exact exception set.
run "the_required_deny_matrix_is_exact_and_derived_from_this_deployment" {
  command = plan

  assert {
    condition     = length(local.required_deny_matrix) == 33 + 4 * 26 && alltrue([for row in values(local.required_deny_matrix) : row.denied == ["principalSet://goog/public:all"]])
    error_message = "The matrix must carry thirty-three broker-project rows and twenty-six rows per consumer project, every one denying every principal."
  }

  assert {
    condition = (
      sort(local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/recovery-test|iam.googleapis.com/serviceAccounts.getAccessToken"].exceptions) == sort(concat(local.invoker_tuples, local.canary_tuples)) &&
      length(local.invoker_tuples) == 8 && length(local.canary_tuples) == 1 && length(local.member_tuples) == 0 &&
      alltrue([for tuple in local.invoker_tuples : startswith(tuple, "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/collinbentley1/platform/.github/workflows/protected-recovery-invoke.yml@refs/heads/main:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:recovery-") && !strcontains(tuple, "*")]) &&
      sort(local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/recovery-test|iam.googleapis.com/serviceAccounts.getOpenIdToken"].exceptions) == sort(concat(["principal://iam.googleapis.com/projects/-/serviceAccounts/service-123456789012@gcp-sa-cloudscheduler.iam.gserviceaccount.com"], local.invoker_tuples)) &&
      local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/recovery-test|datastore.googleapis.com/entities.update"].exceptions == ["principal://iam.googleapis.com/projects/-/serviceAccounts/recovery-broker@recovery-test.iam.gserviceaccount.com"] &&
      local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/recovery-test|storage.googleapis.com/objects.delete"].exceptions == [] &&
      local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/recovery-test|iam.googleapis.com/serviceAccounts.signJwt"].exceptions == [] &&
      local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/recovery-test|run.googleapis.com/services.update"].exceptions == ["principal://goog/subject/cloud-root@cdbentley.com"] &&
      local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/recovery-test|cloudresourcemanager.googleapis.com/projects.setIamPolicy"].exceptions == ["principal://goog/subject/cloud-root@cdbentley.com"] &&
      local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/medlock-1025243085|iam.googleapis.com/serviceAccounts.setIamPolicy"].exceptions == ["principal://goog/subject/cloud-root@cdbentley.com", "principal://iam.googleapis.com/projects/-/serviceAccounts/recovery-broker@recovery-test.iam.gserviceaccount.com"] &&
      local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/cdbentley|cloudresourcemanager.googleapis.com/projects.setIamPolicy"].exceptions == ["principal://goog/subject/cloud-root@cdbentley.com"] &&
      local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/critical-history-16823277|iam.googleapis.com/serviceAccounts.delete"].exceptions == [] &&
      local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/runsetta|iam.googleapis.com/workloadIdentityPools.undelete"].exceptions == [] &&
      local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/runsetta|iam.googleapis.com/serviceAccounts.actAs"].exceptions == [] &&
      local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/cdbentley|run.googleapis.com/services.update"].exceptions == [] &&
      local.required_deny_matrix["cloudresourcemanager.googleapis.com/projects/cdbentley|serviceusage.googleapis.com/services.disable"].exceptions == []
    )
    error_message = "Each row's exception set must be exactly the principals this deployment derives for it: the broker for the ledger and evidence; the exact invoker and canary tuples, never a pool wildcard, for access tokens; the Scheduler agent, the exact invoker tuples, and the exact member tuples for ID tokens; the applying identity for the broker deployment and for the grants its own apply makes in consumer projects; the broker and the applying identity alone for consumer target policies; and nobody for keys, signing, delegation, evidence overwrite, identity lifecycle, federation replacement, workload attachment, and API disablement."
  }

  assert {
    condition = alltrue([for permission in [
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
      "iam.googleapis.com/workloadIdentityPools.create",
      "iam.googleapis.com/workloadIdentityPools.delete",
      "iam.googleapis.com/workloadIdentityPools.undelete",
      "run.googleapis.com/services.create",
      "run.googleapis.com/services.delete",
      ] : contains(keys(local.required_deny_matrix), "cloudresourcemanager.googleapis.com/projects/recovery-test|${permission}")]) && alltrue([for permission in [
      "cloudresourcemanager.googleapis.com/projects.setIamPolicy",
      "iam.googleapis.com/serviceAccounts.create",
      "iam.googleapis.com/serviceAccounts.delete",
      "iam.googleapis.com/serviceAccounts.disable",
      "iam.googleapis.com/serviceAccounts.enable",
      "iam.googleapis.com/workloadIdentityPools.create",
      "iam.googleapis.com/workloadIdentityPools.delete",
      "iam.googleapis.com/workloadIdentityPools.undelete",
      "iam.googleapis.com/workloadIdentityPoolProviders.create",
      "iam.googleapis.com/workloadIdentityPoolProviders.delete",
      "iam.googleapis.com/workloadIdentityPoolProviders.undelete",
      "cloudbuild.googleapis.com/builds.create",
      "compute.googleapis.com/instanceTemplates.create",
      "compute.googleapis.com/instances.create",
      "compute.googleapis.com/instances.setServiceAccount",
      "iam.googleapis.com/serviceAccounts.actAs",
      "run.googleapis.com/jobs.create",
      "run.googleapis.com/jobs.update",
      "run.googleapis.com/services.create",
      "run.googleapis.com/services.update",
      "serviceusage.googleapis.com/services.disable",
    ] : contains(keys(local.required_deny_matrix), "cloudresourcemanager.googleapis.com/projects/runsetta|${permission}")])
    error_message = "Every supported mutation path the review named must be required: project IAM, service-account lifecycle, workload identity pool and provider lifecycle, and Cloud Run service lifecycle at the broker project, and identity, project IAM, federation lifecycle, workload attachment (actAs, Compute, Cloud Run, Cloud Build), and API disablement at every consumer project."
  }

  # Every mutation the module's own apply makes is permitted its principal by
  # the matrix, so the activation sequence -- broker project first, then Deny,
  # then the evidenced grants -- can run without an unevidenced window.
  assert {
    condition     = length(local.activation_blocked) == 0 && length(local.activation_mutations) == 10 + 8 + 8 + 8 + 1 + 1 + 1 + 1 + 4
    error_message = "The required matrix must except the applying identity, the invoker, member, and canary tuples, the Scheduler agent, and the broker for exactly the mutations activation makes; blocked: [${join(", ", local.activation_blocked)}]."
  }
}

# Consistent evidence names records that the mocked GitHub reads do not
# return: even so, the committed target identities are null, so nothing is
# read from any consumer account and nothing is granted.
run "evidence_grants_nothing_while_target_identities_are_unrecorded" {
  command = plan

  variables {
    broker_authority_evidence = {
      organization_id = "100000000001"
      deny_canary = {
        run_id          = "100000000002"
        artifact_id     = "100000000003"
        artifact_sha256 = "abababababababababababababababababababababababababababababababab"
      }
    }
  }

  override_data {
    target = data.google_project.consumer["cdbentley"]
    values = { org_id = "100000000001" }
  }
  override_data {
    target = data.google_project.consumer["critical-history"]
    values = { org_id = "100000000001" }
  }
  override_data {
    target = data.google_project.consumer["healthmcp"]
    values = { org_id = "100000000001" }
  }
  override_data {
    target = data.google_project.consumer["runsetta"]
    values = { org_id = "100000000001" }
  }

  expect_failures = [google_project_iam_custom_role.actuator]
}

run "reject_a_consumer_project_outside_the_evidenced_organization" {
  command = plan

  variables {
    broker_authority_evidence = {
      organization_id = "100000000001"
      deny_canary = {
        run_id          = "100000000002"
        artifact_id     = "100000000003"
        artifact_sha256 = "abababababababababababababababababababababababababababababababab"
      }
    }
  }

  override_data {
    target = data.google_project.consumer["cdbentley"]
    values = { org_id = "100000000001" }
  }
  override_data {
    target = data.google_project.consumer["critical-history"]
    values = { org_id = "100000000001" }
  }
  override_data {
    target = data.google_project.consumer["healthmcp"]
    values = { org_id = "100000000001" }
  }
  override_data {
    target = data.google_project.consumer["runsetta"]
    values = { org_id = "200000000009" }
  }

  expect_failures = [data.google_project.consumer, google_project_iam_custom_role.actuator]
}

run "reject_fabricated_evidence" {
  command = plan

  variables {
    broker_authority_evidence = {
      organization_id = "1"
      deny_canary = {
        run_id          = "pending"
        artifact_id     = "TBD"
        artifact_sha256 = "n/a"
      }
    }
  }

  expect_failures = [var.broker_authority_evidence]
}

run "reject_unpinned_image" {
  command = plan

  variables {
    broker_image = "us-east4-docker.pkg.dev/recovery-test/broker/protected-recovery:latest"
  }

  expect_failures = [var.broker_image]
}

run "reject_short_active_sha" {
  command = plan

  variables {
    active_workflow_sha = "abc123"
  }

  expect_failures = [var.active_workflow_sha]
}

run "reject_transition_sha_equal_to_active_sha" {
  command = plan

  variables {
    transition_workflow_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }

  expect_failures = [var.transition_workflow_sha]
}
