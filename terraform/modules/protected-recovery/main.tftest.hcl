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

# Every invoker grant is one exact job-level tuple of the platform repository:
#   <platform>/protected-recovery-invoke.yml@refs/heads/main:<platform>/protected-recovery-invoke.yml@<sha>:<sha>:recovery-<consumer>:workflow_dispatch
# SHA "a" repeated forty times is the active SHA and "b" the transition SHA;
# "c" is a SHA no binding may ever name. The runs below pin the complete
# consumer -> invoker matrix, prove that neighbouring tuples bind nothing, that
# every invoker holds run.invoker only, that the broker is the only writer, and
# that broker authority over consumer accounts is absent without evidence.

run "provider_admits_only_github_hosted_jobs_of_the_platform_repository" {
  command = plan

  assert {
    condition     = google_iam_workload_identity_pool_provider.platform.attribute_condition == "google.subject.startsWith('16823277:1255856466:github-hosted:')"
    error_message = "The provider condition must be exactly the owner-ID, platform-repository-ID, and GitHub-hosted prefix of the mapped subject, so a consumer repository, a fork, or a self-hosted runner is refused."
  }

  assert {
    condition = google_iam_workload_identity_pool_provider.platform.attribute_mapping == tomap({
      "google.subject"      = "assertion.repository_owner_id + ':' + assertion.repository_id + ':' + assertion.runner_environment + ':' + assertion.run_id"
      "attribute.authority" = "assertion.workflow_ref + ':' + assertion.job_workflow_ref + ':' + assertion.job_workflow_sha + ':' + assertion.environment + ':' + assertion.event_name"
    })
    error_message = "The mapping must be byte-identical to the consumer pools: the subject plus the one job-level authority composite."
  }

  assert {
    condition     = google_iam_workload_identity_pool.platform.workload_identity_pool_id == "github-actions" && google_iam_workload_identity_pool_provider.platform.workload_identity_pool_provider_id == "github" && google_iam_workload_identity_pool_provider.platform.oidc[0].issuer_uri == "https://token.actions.githubusercontent.com/"
    error_message = "Exactly the reviewed pool, provider, and GitHub issuer must be declared."
  }
}

run "active_sha_binds_exactly_the_four_recovery_tuples" {
  command = plan

  assert {
    condition = { for key, binding in google_service_account_iam_member.invoker_authority : key => binding.member } == {
      for consumer in ["cdbentley", "critical-history", "healthmcp", "runsetta"] :
      "${consumer}/${consumer}:workflow_dispatch@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" => "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/collinbentley1/platform/.github/workflows/protected-recovery-invoke.yml@refs/heads/main:collinbentley1/platform/.github/workflows/protected-recovery-invoke.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:recovery-${consumer}:workflow_dispatch"
    }
    error_message = "Active-only trust must bind exactly one workflow_dispatch tuple per consumer invoker and nothing else."
  }

  assert {
    condition = alltrue([
      for binding in values(google_service_account_iam_member.invoker_authority) :
      binding.role == "roles/iam.workloadIdentityUser" && !strcontains(binding.member, "*")
    ])
    error_message = "Every invoker binding must be a wildcard-free Workload Identity User grant."
  }

  assert {
    condition     = length(google_service_account.invoker) == 4 && alltrue([for consumer, account in google_service_account.invoker : account.account_id == "gha-recovery-${consumer}"])
    error_message = "Exactly one purpose-level invoker per consumer, named gha-recovery-<consumer>."
  }
}

run "transition_sha_extends_each_recovery_tuple_once" {
  command = plan

  variables {
    transition_workflow_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }

  assert {
    condition     = length(google_service_account_iam_member.invoker_authority) == 8 && length([for key in keys(google_service_account_iam_member.invoker_authority) : key if endswith(key, "@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]) == 4
    error_message = "A transition SHA must add one tuple beside each active tuple without altering it."
  }

  assert {
    condition = alltrue([
      for key, binding in google_service_account_iam_member.invoker_authority :
      strcontains(binding.member, "@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:") if endswith(key, "@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    ])
    error_message = "Every transition tuple must carry job_workflow_ref and job_workflow_sha at that same SHA."
  }
}

run "neighbouring_tuples_bind_nothing" {
  command = plan

  variables {
    transition_workflow_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }

  # caller repository, caller workflow, caller ref, reusable workflow, ref SHA, job SHA, environment, event
  assert {
    condition = length([
      for pair in [
        ["collinbentley1/cdbentley", "protected-recovery-invoke.yml", "refs/heads/main", "protected-recovery-invoke.yml", "a", "a", "recovery-cdbentley", "workflow_dispatch"],
        ["evil/platform", "protected-recovery-invoke.yml", "refs/heads/main", "protected-recovery-invoke.yml", "a", "a", "recovery-cdbentley", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-bootstrap-implementation.yml", "refs/heads/main", "protected-recovery-invoke.yml", "a", "a", "recovery-cdbentley", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/feature", "protected-recovery-invoke.yml", "a", "a", "recovery-cdbentley", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "deploy-prod.yml", "a", "a", "recovery-cdbentley", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "protected-recovery-invoke.yml", "c", "c", "recovery-cdbentley", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "protected-recovery-invoke.yml", "a", "b", "recovery-cdbentley", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "protected-recovery-invoke.yml", "a", "a", "recovery-runsetta", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "protected-recovery-invoke.yml", "a", "a", "production", "workflow_dispatch"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "protected-recovery-invoke.yml", "a", "a", "recovery-cdbentley", "push"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "protected-recovery-invoke.yml", "a", "a", "recovery-cdbentley", "pull_request_target"],
        ["collinbentley1/platform", "protected-recovery-invoke.yml", "refs/heads/main", "protected-recovery-invoke.yml", "a", "a", "supply-chain", "workflow_dispatch"],
      ] : pair
      if contains(
        [for key, binding in google_service_account_iam_member.invoker_authority : binding.member if startswith(key, "cdbentley/")],
        "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/${pair[0]}/.github/workflows/${pair[1]}@${pair[2]}:collinbentley1/platform/.github/workflows/${pair[3]}@${join("", [for i in range(40) : pair[4]])}:${join("", [for i in range(40) : pair[5]])}:${pair[6]}:${pair[7]}",
      )
    ]) == 0
    error_message = "A tuple that differs in caller repository, workflow, or branch; in reusable workflow or SHA; in job_workflow_sha; in environment; or in event must remain unbound, and one consumer's invoker must never accept another consumer's tuple."
  }

  assert {
    condition     = length([for binding in values(google_service_account_iam_member.invoker_authority) : binding.member if strcontains(binding.member, ":supply-chain:") || strcontains(binding.member, "/deploy-prod.yml@") || strcontains(binding.member, "/cdbentley/")]) == 0
    error_message = "No attestation, deploy, or consumer-repository tuple may reach a recovery invoker."
  }
}

run "invokers_hold_only_run_invoker_and_the_broker_is_the_only_writer" {
  command = plan

  assert {
    condition     = keys(google_cloud_run_v2_service_iam_member.invokers) == ["cdbentley", "critical-history", "healthmcp", "reconciler", "runsetta"] && alltrue([for grant in values(google_cloud_run_v2_service_iam_member.invokers) : grant.role == "roles/run.invoker"])
    error_message = "Exactly the four invokers and the reconciler hold run.invoker on the broker, and nothing else."
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
    condition     = length(google_project_iam_custom_role.actuator) == 0 && length(google_service_account_iam_member.actuator) == 0
    error_message = "Without organization and Deny evidence the module must grant the broker nothing in any consumer project."
  }
}

run "evidence_grants_exactly_the_actuator_role_on_every_consumer_target" {
  command = plan

  variables {
    broker_authority_evidence = {
      deny_canary_run_id = "1"
      organization_id    = "1"
    }
  }

  assert {
    condition     = keys(google_project_iam_custom_role.actuator) == ["cdbentley", "critical-history", "healthmcp", "runsetta"] && alltrue([for role in values(google_project_iam_custom_role.actuator) : role.permissions == toset(["iam.serviceAccounts.getIamPolicy", "iam.serviceAccounts.setIamPolicy"]) && role.role_id == "protectedRecoveryActuator"])
    error_message = "One actuator role per consumer project with exactly getIamPolicy and setIamPolicy."
  }

  assert {
    condition = length(google_service_account_iam_member.actuator) == 36 && alltrue(flatten([
      for consumer in ["cdbentley", "critical-history", "healthmcp", "runsetta"] : [
        for account in ["gha-deploy-parity", "gha-preview-commit", "gha-preview-deploy", "gha-preview-operator", "gha-preview-publish", "gha-prod-deploy", "gha-prod-publish", "gha-terraform", "gha-wif-canary"] :
        contains(keys(google_service_account_iam_member.actuator), "${consumer}/${account}")
      ]
    ]))
    error_message = "Exactly the thirty-six (consumer, federated account) grants and no other resource."
  }

  assert {
    condition = alltrue([
      for key, grant in google_service_account_iam_member.actuator :
      grant.service_account_id == "projects/${local.consumers[split("/", key)[0]].projectId}/serviceAccounts/${split("/", key)[1]}@${local.consumers[split("/", key)[0]].projectId}.iam.gserviceaccount.com"
    ])
    error_message = "Every actuator grant must name the exact consumer service account resource."
  }
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

run "reject_fabricated_evidence" {
  command = plan

  variables {
    broker_authority_evidence = {
      deny_canary_run_id = "pending"
      organization_id    = "TBD"
    }
  }

  expect_failures = [var.broker_authority_evidence]
}
