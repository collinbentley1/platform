mock_provider "google" {}

override_data {
  target = data.google_project.current
  values = {
    number = "123456789012"
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
# nothing, that every invoker holds run.invoker only, that the broker is the
# only writer, and that broker authority over consumer accounts is absent
# without evidence and refused for every evidence an offline input can produce.
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
    condition     = keys(google_cloud_run_v2_service_iam_member.invokers) == ["cdbentley/QUARANTINE", "cdbentley/RESTORE", "critical-history/QUARANTINE", "critical-history/RESTORE", "healthmcp/QUARANTINE", "healthmcp/RESTORE", "reconciler", "runsetta/QUARANTINE", "runsetta/RESTORE"] && alltrue([for grant in values(google_cloud_run_v2_service_iam_member.invokers) : grant.role == "roles/run.invoker"])
    error_message = "Exactly the eight direction-bound invokers and the reconciler hold run.invoker on the broker, and nothing else."
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
        [for grant in values(google_cloud_run_v2_service_iam_member.invokers) : grant.role],
        [for grant in values(google_storage_bucket_iam_member.broker_evidence) : grant.role],
        [google_project_iam_member.broker_ledger.role],
      ) : role
      if contains(["roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountKeyAdmin", "roles/iam.serviceAccountAdmin", "roles/iam.workloadIdentityPoolAdmin", "roles/owner", "roles/editor", "roles/datastore.owner", "roles/storage.admin", "roles/run.admin"], role)
    ]) == 0
    error_message = "No grant may create tokens or keys, administer service accounts or pools, or hold a basic or admin role."
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
}

run "broker_authority_over_consumer_accounts_is_absent_without_evidence" {
  command = plan

  assert {
    condition     = length(google_project_iam_custom_role.actuator) == 0 && length(google_service_account_iam_member.actuator) == 0 && length(data.google_project.consumer) == 0
    error_message = "Without evidence the module must grant the broker nothing in any consumer project and must not even read the consumer projects."
  }

  assert {
    condition     = length(local.unrecorded_identities) == 36 && !local.identities_recorded
    error_message = "The committed authority records no target identity; all thirty-six (consumer, account) identities must be unrecorded until a reviewed change records the real ones."
  }
}

# Consistent with every offline-checkable binding: this plan's image digest
# and active SHA, a successful canary at that SHA, the complete required
# coverage with the broker excepted, and a live organization that (in these
# mocked runs) parents every consumer project. Even this evidence grants
# nothing, because the committed target identities are null.
run "consistent_evidence_grants_nothing_while_target_identities_are_unrecorded" {
  command = plan

  variables {
    broker_authority_evidence = {
      organization_id = "100000000001"
      platform_sha    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      broker_image    = "us-east4-docker.pkg.dev/recovery-test/broker/protected-recovery@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      deny_canary = {
        run_id          = "100000000002"
        head_sha        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        conclusion      = "success"
        artifact_sha256 = "abababababababababababababababababababababababababababababababab"
        permissions = [
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
        ]
        exceptions = ["principal://iam.googleapis.com/projects/-/serviceAccounts/recovery-broker@recovery-test.iam.gserviceaccount.com"]
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
      platform_sha    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      broker_image    = "us-east4-docker.pkg.dev/recovery-test/broker/protected-recovery@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      deny_canary = {
        run_id          = "100000000002"
        head_sha        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        conclusion      = "success"
        artifact_sha256 = "abababababababababababababababababababababababababababababababab"
        permissions = [
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
        ]
        exceptions = ["principal://iam.googleapis.com/projects/-/serviceAccounts/recovery-broker@recovery-test.iam.gserviceaccount.com"]
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

run "reject_evidence_for_another_image" {
  command = plan

  variables {
    broker_authority_evidence = {
      organization_id = "100000000001"
      platform_sha    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      broker_image    = "us-east4-docker.pkg.dev/recovery-test/broker/protected-recovery@sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
      deny_canary = {
        run_id          = "100000000002"
        head_sha        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        conclusion      = "success"
        artifact_sha256 = "abababababababababababababababababababababababababababababababab"
        permissions     = ["storage.googleapis.com/objects.create"]
        exceptions      = ["principal://iam.googleapis.com/projects/-/serviceAccounts/recovery-broker@recovery-test.iam.gserviceaccount.com"]
      }
    }
  }

  expect_failures = [var.broker_authority_evidence]
}

run "reject_evidence_for_another_platform_revision" {
  command = plan

  variables {
    broker_authority_evidence = {
      organization_id = "100000000001"
      platform_sha    = "cccccccccccccccccccccccccccccccccccccccc"
      broker_image    = "us-east4-docker.pkg.dev/recovery-test/broker/protected-recovery@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      deny_canary = {
        run_id          = "100000000002"
        head_sha        = "cccccccccccccccccccccccccccccccccccccccc"
        conclusion      = "success"
        artifact_sha256 = "abababababababababababababababababababababababababababababababab"
        permissions     = ["storage.googleapis.com/objects.create"]
        exceptions      = ["principal://iam.googleapis.com/projects/-/serviceAccounts/recovery-broker@recovery-test.iam.gserviceaccount.com"]
      }
    }
  }

  expect_failures = [var.broker_authority_evidence]
}

run "reject_a_canary_that_did_not_succeed_or_covers_less_than_required" {
  command = plan

  variables {
    broker_authority_evidence = {
      organization_id = "100000000001"
      platform_sha    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      broker_image    = "us-east4-docker.pkg.dev/recovery-test/broker/protected-recovery@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      deny_canary = {
        run_id          = "100000000002"
        head_sha        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        conclusion      = "failure"
        artifact_sha256 = "abababababababababababababababababababababababababababababababab"
        permissions     = ["storage.googleapis.com/objects.create"]
        exceptions      = []
      }
    }
  }

  expect_failures = [var.broker_authority_evidence]
}

run "reject_fabricated_evidence" {
  command = plan

  variables {
    broker_authority_evidence = {
      organization_id = "1"
      platform_sha    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      broker_image    = "us-east4-docker.pkg.dev/recovery-test/broker/protected-recovery@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      deny_canary = {
        run_id          = "pending"
        head_sha        = "TBD"
        conclusion      = "success"
        artifact_sha256 = "n/a"
        permissions     = []
        exceptions      = []
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
