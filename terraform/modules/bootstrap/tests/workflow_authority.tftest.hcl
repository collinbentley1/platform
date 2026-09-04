mock_provider "google" {}

override_data {
  target = data.google_project.current
  values = {
    number = "123456789012"
  }
}

variables {
  app                                                    = "example"
  project_id                                             = "example"
  region                                                 = "us-east4"
  state_bucket_name                                      = "example-tfstate"
  bootstrap_state_bucket_name                            = "example-bootstrap-tfstate"
  state_bucket_location                                  = "US-EAST4"
  github_owner                                           = "collinbentley1"
  github_repo                                            = "example"
  github_repository_id                                   = "123456789"
  active_workflow_sha                                    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  manage_automatic_default_service_account_grants_policy = false
}

# Every federated grant in this module is one exact job-level tuple:
#   <consumer>/<caller>@refs/heads/main:<platform>/<workflow>@<sha>:<sha>:<environment>:<event>
# The runs below pin the complete authorized tuple -> account matrix and prove
# that neighbouring tuples, unauthorized accounts, and every non-federated path
# stay unbound. SHA "a" repeated forty times is the active SHA and "b" the
# transition SHA; "c" is a SHA no binding may ever name.

run "provider_admits_only_github_hosted_jobs_of_the_exact_repository" {
  command = plan

  assert {
    condition     = google_iam_workload_identity_pool_provider.github.attribute_condition == "google.subject.startsWith('16823277:123456789:github-hosted:')"
    error_message = "The provider condition must be exactly the owner-ID, repository-ID, and GitHub-hosted prefix of the mapped subject, so a wrong owner, a wrong repository, or a self-hosted runner is refused."
  }

  assert {
    condition = google_iam_workload_identity_pool_provider.github.attribute_mapping == tomap({
      "google.subject"      = "assertion.repository_owner_id + ':' + assertion.repository_id + ':' + assertion.runner_environment + ':' + assertion.run_id"
      "attribute.authority" = "assertion.workflow_ref + ':' + assertion.job_workflow_ref + ':' + assertion.job_workflow_sha + ':' + assertion.environment + ':' + assertion.event_name"
    })
    error_message = "The mapping must be the subject plus the one job-level authority composite in tuple order, with no per-job decision logic."
  }

  assert {
    condition     = !strcontains(google_iam_workload_identity_pool_provider.github.attribute_condition, "run_attempt") && !strcontains(google_iam_workload_identity_pool_provider.github.attribute_mapping["attribute.authority"], "run_attempt")
    error_message = "Neither the condition nor the authority composite may depend on run_attempt, so both attempts of a run carry identical IAM authority."
  }

  assert {
    condition     = google_iam_workload_identity_pool.github.workload_identity_pool_id == "github-actions" && google_iam_workload_identity_pool_provider.github.workload_identity_pool_provider_id == "github" && google_iam_workload_identity_pool_provider.github.oidc[0].issuer_uri == "https://token.actions.githubusercontent.com/"
    error_message = "Exactly the reviewed pool, provider, and GitHub issuer must be declared."
  }
}

run "active_sha_binds_the_exact_job_tuple_matrix" {
  command = plan

  assert {
    condition = { for key, binding in google_service_account_iam_member.workflow_authority : key => binding.member } == {
      for row in [
        # account, reusable workflow, job, caller workflow, event, environment
        ["gha-preview-commit", "cleanup-preview.yml", "cleanup", "cleanup-preview.yml", "pull_request_target", "preview-operations"],
        ["gha-preview-commit", "cleanup-preview.yml", "cleanup", "deploy-preview.yml", "pull_request_target", "preview-operations"],
        ["gha-preview-operator", "cleanup-preview.yml", "cleanup", "cleanup-preview.yml", "pull_request_target", "preview-operations"],
        ["gha-preview-operator", "cleanup-preview.yml", "cleanup", "deploy-preview.yml", "pull_request_target", "preview-operations"],
        ["gha-wif-canary", "cleanup-preview.yml", "cleanup", "cleanup-preview.yml", "pull_request_target", "preview-operations"],
        ["gha-wif-canary", "cleanup-preview.yml", "cleanup", "deploy-preview.yml", "pull_request_target", "preview-operations"],
        ["gha-wif-canary", "deploy-preview.yml", "canary", "deploy-preview.yml", "pull_request_target", "preview-cloud-canary"],
        ["gha-deploy-parity", "deploy-preview.yml", "deploy", "deploy-preview.yml", "pull_request_target", "preview-cloud"],
        ["gha-preview-commit", "deploy-preview.yml", "deploy", "deploy-preview.yml", "pull_request_target", "preview-cloud"],
        ["gha-preview-deploy", "deploy-preview.yml", "deploy", "deploy-preview.yml", "pull_request_target", "preview-cloud"],
        ["gha-preview-operator", "deploy-preview.yml", "deploy", "deploy-preview.yml", "pull_request_target", "preview-cloud"],
        ["gha-preview-commit", "deploy-preview.yml", "invalidate", "deploy-preview.yml", "pull_request_target", "preview-operations"],
        ["gha-preview-operator", "deploy-preview.yml", "invalidate", "deploy-preview.yml", "pull_request_target", "preview-operations"],
        ["gha-wif-canary", "deploy-preview.yml", "invalidate", "deploy-preview.yml", "pull_request_target", "preview-operations"],
        ["gha-preview-publish", "deploy-preview.yml", "publish", "deploy-preview.yml", "pull_request_target", "preview-publish"],
        ["gha-wif-canary", "deploy-preview.yml", "publish", "deploy-preview.yml", "pull_request_target", "preview-publish"],
        ["gha-wif-canary", "deploy-preview.yml", "publish-canary", "deploy-preview.yml", "pull_request_target", "preview-publish-canary"],
        ["gha-wif-canary", "deploy-prod.yml", "canary", "deploy-prod.yml", "push", "production-canary"],
        ["gha-deploy-parity", "deploy-prod.yml", "deploy", "deploy-prod.yml", "push", "production"],
        ["gha-preview-commit", "deploy-prod.yml", "deploy", "deploy-prod.yml", "push", "production"],
        ["gha-preview-deploy", "deploy-prod.yml", "deploy", "deploy-prod.yml", "push", "production"],
        ["gha-prod-deploy", "deploy-prod.yml", "deploy", "deploy-prod.yml", "push", "production"],
        ["gha-prod-publish", "deploy-prod.yml", "publish", "deploy-prod.yml", "push", "production-publish"],
        ["gha-wif-canary", "deploy-prod.yml", "publish", "deploy-prod.yml", "push", "production-publish"],
        ["gha-terraform", "infrastructure.yml", "terraform-convergence", "deploy-prod.yml", "push", "production"],
        ["gha-wif-canary", "infrastructure.yml", "terraform-convergence", "deploy-prod.yml", "push", "production"],
        ["gha-preview-commit", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "push", "preview-operations"],
        ["gha-preview-commit", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "schedule", "preview-operations"],
        ["gha-preview-commit", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "workflow_dispatch", "preview-operations"],
        ["gha-preview-operator", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "push", "preview-operations"],
        ["gha-preview-operator", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "schedule", "preview-operations"],
        ["gha-preview-operator", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "workflow_dispatch", "preview-operations"],
        ["gha-wif-canary", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "push", "preview-operations"],
        ["gha-wif-canary", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "schedule", "preview-operations"],
        ["gha-wif-canary", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "workflow_dispatch", "preview-operations"],
      ] : "${row[0]}/${row[1]}:${row[2]}/${row[3]}:${row[4]}@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" => "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/collinbentley1/example/.github/workflows/${row[3]}@refs/heads/main:collinbentley1/platform/.github/workflows/${row[1]}@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:${row[5]}:${row[4]}"
    }
    error_message = "Active-only trust must bind exactly these thirty-five job-level tuples and nothing else: the supply-chain attestation tuples bind no account, each canary tuple binds only gha-wif-canary, preview-operations tuples bind only the committer, the IAM auditor, and the canary, and no transition SHA appears."
  }

  assert {
    condition = alltrue([
      for binding in values(google_service_account_iam_member.workflow_authority) :
      binding.role == "roles/iam.workloadIdentityUser" && !strcontains(binding.member, "*") && startswith(binding.member, "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/collinbentley1/example/.github/workflows/")
    ])
    error_message = "Every federated binding must be a wildcard-free Workload Identity User grant on an exact tuple whose caller is this consumer repository."
  }
}

run "transition_sha_extends_only_the_preview_operations_tuples" {
  command = plan

  variables {
    transition_workflow_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }

  assert {
    condition     = length(google_service_account_iam_member.workflow_authority) == 50 && length([for key in keys(google_service_account_iam_member.workflow_authority) : key if endswith(key, "@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]) == 35
    error_message = "A transition SHA must add tuples beside the thirty-five active ones without altering them."
  }

  assert {
    condition = { for key, binding in google_service_account_iam_member.workflow_authority : key => binding.member if endswith(key, "@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") } == {
      for row in [
        ["gha-preview-commit", "cleanup-preview.yml", "cleanup", "cleanup-preview.yml", "pull_request_target"],
        ["gha-preview-commit", "cleanup-preview.yml", "cleanup", "deploy-preview.yml", "pull_request_target"],
        ["gha-preview-operator", "cleanup-preview.yml", "cleanup", "cleanup-preview.yml", "pull_request_target"],
        ["gha-preview-operator", "cleanup-preview.yml", "cleanup", "deploy-preview.yml", "pull_request_target"],
        ["gha-wif-canary", "cleanup-preview.yml", "cleanup", "cleanup-preview.yml", "pull_request_target"],
        ["gha-wif-canary", "cleanup-preview.yml", "cleanup", "deploy-preview.yml", "pull_request_target"],
        ["gha-preview-commit", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "push"],
        ["gha-preview-commit", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "schedule"],
        ["gha-preview-commit", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "workflow_dispatch"],
        ["gha-preview-operator", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "push"],
        ["gha-preview-operator", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "schedule"],
        ["gha-preview-operator", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "workflow_dispatch"],
        ["gha-wif-canary", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "push"],
        ["gha-wif-canary", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "schedule"],
        ["gha-wif-canary", "reconcile-previews.yml", "reconcile", "reconcile-previews.yml", "workflow_dispatch"],
      ] : "${row[0]}/${row[1]}:${row[2]}/${row[3]}:${row[4]}@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" => "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/collinbentley1/example/.github/workflows/${row[3]}@refs/heads/main:collinbentley1/platform/.github/workflows/${row[1]}@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:preview-operations:${row[4]}"
    }
    error_message = "The transition SHA may bind only the fifteen cleanup and reconcile tuples, each with job_workflow_ref and job_workflow_sha at that same SHA."
  }

  assert {
    condition = length([
      for binding in values(google_service_account_iam_member.workflow_authority) : binding.member
      if strcontains(binding.member, "/deploy-prod.yml@bbbb") || strcontains(binding.member, "/deploy-preview.yml@bbbb") || strcontains(binding.member, "/infrastructure.yml@bbbb")
    ]) == 0
    error_message = "A predecessor token must never deploy, publish, attest, run a canary, or converge infrastructure."
  }
}

run "neighbouring_tuples_and_unauthorized_accounts_bind_nothing" {
  command = plan

  variables {
    transition_workflow_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }

  # Positive controls: the exact tuples are bound to the accounts that exchange
  # through them, so the negatives below are not vacuous.
  assert {
    condition = alltrue([
      for pair in [
        ["gha-prod-deploy", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production", "push"],
        ["gha-wif-canary", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production-canary", "push"],
        ["gha-preview-commit", "collinbentley1/example", "deploy-preview.yml", "refs/heads/main", "collinbentley1/platform", "cleanup-preview.yml", "b", "b", "preview-operations", "pull_request_target"],
        ["gha-terraform", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "infrastructure.yml", "a", "a", "production", "push"],
      ] :
      contains(
        [for key, binding in google_service_account_iam_member.workflow_authority : binding.member if startswith(key, "${pair[0]}/")],
        "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/${pair[1]}/.github/workflows/${pair[2]}@${pair[3]}:${pair[4]}/.github/workflows/${pair[5]}@${join("", [for i in range(40) : pair[6]])}:${join("", [for i in range(40) : pair[7]])}:${pair[8]}:${pair[9]}",
      )
    ])
    error_message = "The exact production deploy, production canary, transition cleanup, and convergence tuples must be bound to the accounts that exchange through them."
  }

  # account, consumer, caller, caller ref, reusable repository, reusable workflow, ref SHA, job SHA, environment, event
  assert {
    condition = length([
      for pair in [
        # The caller is the wrong owner, repository, workflow file, or branch.
        ["gha-prod-deploy", "evil/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production", "push"],
        ["gha-prod-deploy", "collinbentley1/other", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production", "push"],
        ["gha-prod-deploy", "collinbentley1/example", "deploy-preview.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production", "push"],
        ["gha-prod-deploy", "collinbentley1/example", "deploy-prod.yml", "refs/heads/feature", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production", "push"],
        ["gha-preview-commit", "collinbentley1/example", "reconcile-previews.yml", "refs/heads/feature", "collinbentley1/platform", "reconcile-previews.yml", "a", "a", "preview-operations", "workflow_dispatch"],
        # The reusable workflow is the wrong repository, path, or SHA, or its job_workflow_sha disagrees with its ref.
        ["gha-prod-deploy", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "evil/platform", "deploy-prod.yml", "a", "a", "production", "push"],
        ["gha-prod-deploy", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-preview.yml", "a", "a", "production", "push"],
        ["gha-prod-deploy", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "b", "b", "production", "push"],
        ["gha-prod-deploy", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "c", "c", "production", "push"],
        ["gha-prod-deploy", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "b", "production", "push"],
        ["gha-preview-commit", "collinbentley1/example", "cleanup-preview.yml", "refs/heads/main", "collinbentley1/platform", "cleanup-preview.yml", "b", "a", "preview-operations", "pull_request_target"],
        ["gha-preview-commit", "collinbentley1/example", "cleanup-preview.yml", "refs/heads/main", "collinbentley1/platform", "cleanup-preview.yml", "a", "b", "preview-operations", "pull_request_target"],
        # The environment or the event is wrong for an otherwise exact tuple.
        ["gha-prod-deploy", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production-canary", "push"],
        ["gha-prod-deploy", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "supply-chain", "push"],
        ["gha-prod-deploy", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production", "pull_request_target"],
        ["gha-prod-deploy", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production", "workflow_dispatch"],
        ["gha-preview-deploy", "collinbentley1/example", "deploy-preview.yml", "refs/heads/main", "collinbentley1/platform", "deploy-preview.yml", "a", "a", "preview-cloud", "pull_request"],
        ["gha-preview-deploy", "collinbentley1/example", "deploy-preview.yml", "refs/heads/main", "collinbentley1/platform", "deploy-preview.yml", "a", "a", "preview-cloud-canary", "pull_request_target"],
        ["gha-preview-publish", "collinbentley1/example", "deploy-preview.yml", "refs/heads/main", "collinbentley1/platform", "deploy-preview.yml", "a", "a", "preview-publish-canary", "pull_request_target"],
        ["gha-preview-commit", "collinbentley1/example", "reconcile-previews.yml", "refs/heads/main", "collinbentley1/platform", "reconcile-previews.yml", "a", "a", "preview-operations", "pull_request_target"],
        # Accounts a tuple never exchanges for, including every deployer and publisher outside its own job.
        ["gha-wif-canary", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production", "push"],
        ["gha-prod-publish", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production", "push"],
        ["gha-terraform", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production", "push"],
        ["gha-prod-deploy", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production-publish", "push"],
        ["gha-preview-publish", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "deploy-prod.yml", "a", "a", "production-publish", "push"],
        ["gha-prod-deploy", "collinbentley1/example", "deploy-prod.yml", "refs/heads/main", "collinbentley1/platform", "infrastructure.yml", "a", "a", "production", "push"],
        ["gha-prod-deploy", "collinbentley1/example", "deploy-preview.yml", "refs/heads/main", "collinbentley1/platform", "deploy-preview.yml", "a", "a", "preview-cloud", "pull_request_target"],
        ["gha-prod-publish", "collinbentley1/example", "deploy-preview.yml", "refs/heads/main", "collinbentley1/platform", "deploy-preview.yml", "a", "a", "preview-publish", "pull_request_target"],
        ["gha-preview-deploy", "collinbentley1/example", "cleanup-preview.yml", "refs/heads/main", "collinbentley1/platform", "cleanup-preview.yml", "a", "a", "preview-operations", "pull_request_target"],
        ["gha-preview-deploy", "collinbentley1/example", "deploy-preview.yml", "refs/heads/main", "collinbentley1/platform", "deploy-preview.yml", "a", "a", "preview-operations", "pull_request_target"],
        ["gha-preview-deploy", "collinbentley1/example", "reconcile-previews.yml", "refs/heads/main", "collinbentley1/platform", "reconcile-previews.yml", "a", "a", "preview-operations", "schedule"],
        ["gha-deploy-parity", "collinbentley1/example", "reconcile-previews.yml", "refs/heads/main", "collinbentley1/platform", "reconcile-previews.yml", "a", "a", "preview-operations", "push"],
      ] : pair
      if contains(
        [for key, binding in google_service_account_iam_member.workflow_authority : binding.member if startswith(key, "${pair[0]}/")],
        "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/${pair[1]}/.github/workflows/${pair[2]}@${pair[3]}:${pair[4]}/.github/workflows/${pair[5]}@${join("", [for i in range(40) : pair[6]])}:${join("", [for i in range(40) : pair[7]])}:${pair[8]}:${pair[9]}",
      )
    ]) == 0
    error_message = "A tuple that differs in caller owner, repository, workflow, or branch; in reusable repository, path, or SHA; in job_workflow_sha; in environment; or in event, and an account a job never exchanges for, must all remain unbound."
  }

  assert {
    condition     = length([for binding in values(google_service_account_iam_member.workflow_authority) : binding.member if strcontains(binding.member, ":supply-chain:")]) == 0
    error_message = "The supply-chain attestation tuples must bind no Google service account even though they hold id-token: write."
  }

  assert {
    condition = alltrue([
      for key, binding in google_service_account_iam_member.workflow_authority :
      startswith(key, "gha-wif-canary/") if strcontains(binding.member, "-canary:")
    ])
    error_message = "Every canary tuple must bind only the no-role gha-wif-canary account."
  }

  assert {
    condition = alltrue([
      for key, binding in google_service_account_iam_member.workflow_authority :
      contains(["gha-preview-commit", "gha-preview-operator", "gha-wif-canary"], split("/", key)[0]) if strcontains(binding.member, ":preview-operations:")
    ])
    error_message = "preview-operations tuples may authenticate only the committer, the IAM auditor, and the canary; never a deployer, publisher, parity reader, or Terraform identity."
  }
}

run "each_module_instance_binds_only_its_own_consumer_repository" {
  command = plan

  variables {
    github_repo          = "other"
    github_repository_id = "987654321"
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github.attribute_condition == "google.subject.startsWith('16823277:987654321:github-hosted:')"
    error_message = "The provider condition must track the exact consumer repository ID of the module instance."
  }

  assert {
    condition = alltrue([
      for binding in values(google_service_account_iam_member.workflow_authority) :
      startswith(binding.member, "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/collinbentley1/other/.github/workflows/")
    ])
    error_message = "Every tuple must name this module instance's consumer repository as its caller, so one consumer's caller can never satisfy another project's binding."
  }
}

run "federated_principals_reach_only_bound_service_accounts" {
  command = plan

  assert {
    condition = alltrue(concat(
      [for grant in values(google_project_iam_member.preview_iam_auditors) : startswith(grant.member, "serviceAccount:")],
      [for grant in values(google_project_iam_member.runtime_project_roles) : startswith(grant.member, "serviceAccount:")],
      [for grant in google_project_iam_member.prod_deploy_waitlist_recaptcha_key_reader : startswith(grant.member, "serviceAccount:")],
      [for grant in google_project_iam_member.runtime_waitlist_challenge_sender : startswith(grant.member, "serviceAccount:")],
      [startswith(google_project_iam_member.terraform_convergence_reader.member, "serviceAccount:")],
      [startswith(google_storage_bucket_iam_member.terraform_state_reader.member, "serviceAccount:")],
      [startswith(google_storage_bucket_iam_member.preview_commit_transition_coordinator.member, "serviceAccount:")],
      [google_storage_bucket_iam_member.terraform_state_access_logs_writer.member == "group:cloud-storage-analytics@google.com"],
      [length(google_project_iam_binding.editor_absent.members) == 0],
    ))
    error_message = "No project, bucket, or pool-wide grant may name a federated principal: Workload Identity User on a bound service account is the only door."
  }

  assert {
    condition = alltrue([
      for grant in [google_service_account_iam_member.prod_deploy_uses_runtime, google_service_account_iam_member.preview_deploy_uses_preview_runtime] :
      grant.role == "roles/iam.serviceAccountUser" && startswith(grant.member, "serviceAccount:")
    ])
    error_message = "The only service-account-to-service-account grants are the two deployer actAs grants on their runtime identities, held by service accounts rather than federated principals."
  }

  assert {
    condition = length([
      for role in concat(
        [for grant in values(google_project_iam_member.runtime_project_roles) : grant.role],
        [
          google_service_account_iam_member.prod_deploy_uses_runtime.role,
          google_service_account_iam_member.preview_deploy_uses_preview_runtime.role,
          google_storage_bucket_iam_member.terraform_state_reader.role,
          google_storage_bucket_iam_member.terraform_state_access_logs_writer.role,
        ],
      ) : role
      if contains(["roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountKeyAdmin", "roles/iam.serviceAccountAdmin", "roles/iam.workloadIdentityPoolAdmin", "roles/iam.workloadIdentityUser", "roles/owner", "roles/editor"], role)
    ]) == 0 && alltrue([for grant in values(google_service_account_iam_member.workflow_authority) : grant.role == "roles/iam.workloadIdentityUser"])
    error_message = "No grant may create tokens or keys, administer service accounts or pools, or hold a basic role; federated principals hold Workload Identity User and nothing else."
  }
}

run "reject_short_active_sha" {
  command = plan

  variables {
    active_workflow_sha = "abc123"
  }

  expect_failures = [var.active_workflow_sha]
}

run "reject_uppercase_transition_sha" {
  command = plan

  variables {
    transition_workflow_sha = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
  }

  expect_failures = [var.transition_workflow_sha]
}

run "reject_transition_sha_equal_to_active_sha" {
  command = plan

  variables {
    transition_workflow_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }

  expect_failures = [var.transition_workflow_sha]
}
