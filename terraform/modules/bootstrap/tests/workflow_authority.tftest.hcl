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

run "provider_trusts_only_the_owner_and_repository_ids" {
  command = plan

  assert {
    condition     = google_iam_workload_identity_pool_provider.github.attribute_condition == "assertion.repository_owner_id == '16823277' && assertion.repository_id == '123456789'"
    error_message = "The provider condition must be the literal owner-ID and repository-ID conjunction and nothing else."
  }

  assert {
    condition = google_iam_workload_identity_pool_provider.github.attribute_mapping == tomap({
      "google.subject"             = "assertion.repository_owner_id + ':' + assertion.repository_id + ':' + assertion.run_id"
      "attribute.repository_id"    = "assertion.repository_id"
      "attribute.job_workflow_ref" = "assertion.job_workflow_ref"
    })
    error_message = "The attribute mapping must be the plain three-entry map."
  }

  assert {
    condition     = google_iam_workload_identity_pool.github.workload_identity_pool_id == "github-actions" && google_iam_workload_identity_pool_provider.github.workload_identity_pool_provider_id == "github"
    error_message = "Exactly the reviewed pool and provider identifiers must be declared."
  }
}

run "active_sha_binds_every_cloud_workflow_authority" {
  command = plan

  assert {
    condition = keys(google_service_account_iam_member.workflow_authority) == [
      "gha-deploy-parity/.github/workflows/deploy-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-deploy-parity/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-commit/.github/workflows/cleanup-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-commit/.github/workflows/deploy-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-commit/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-commit/.github/workflows/reconcile-previews.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-deploy/.github/workflows/deploy-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-deploy/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-operator/.github/workflows/cleanup-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-operator/.github/workflows/deploy-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-operator/.github/workflows/reconcile-previews.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-publish/.github/workflows/deploy-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-prod-deploy/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-prod-publish/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-terraform/.github/workflows/infrastructure.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-wif-canary/.github/workflows/cleanup-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-wif-canary/.github/workflows/deploy-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-wif-canary/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-wif-canary/.github/workflows/infrastructure.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-wif-canary/.github/workflows/reconcile-previews.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]
    error_message = "Active-only trust must bind exactly the manifest's twenty cloud workflow authorities and no transition SHA."
  }

  assert {
    condition     = google_service_account_iam_member.workflow_authority["gha-terraform/.github/workflows/infrastructure.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"].member == "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.job_workflow_ref/collinbentley1/platform/.github/workflows/infrastructure.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    error_message = "Each member must be the exact job_workflow_ref principalSet for its path@SHA."
  }

  assert {
    condition     = google_service_account_iam_member.workflow_authority["gha-prod-deploy/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"].member == "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.job_workflow_ref/collinbentley1/platform/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    error_message = "The production deployer must trust only the exact production workflow reference."
  }

  assert {
    condition = alltrue([
      for binding in values(google_service_account_iam_member.workflow_authority) :
      binding.role == "roles/iam.workloadIdentityUser" && !strcontains(binding.member, "*") && startswith(binding.member, "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.job_workflow_ref/collinbentley1/platform/.github/workflows/")
    ])
    error_message = "Every federated binding must be a wildcard-free Workload Identity User grant on an exact platform workflow reference."
  }

  assert {
    condition = alltrue(concat(
      [for grant in values(google_project_iam_member.preview_iam_auditors) : startswith(grant.member, "serviceAccount:")],
      [for grant in values(google_project_iam_member.runtime_project_roles) : startswith(grant.member, "serviceAccount:")],
      [startswith(google_project_iam_member.terraform_convergence_reader.member, "serviceAccount:")],
      [startswith(google_storage_bucket_iam_member.terraform_state_reader.member, "serviceAccount:")],
      [startswith(google_storage_bucket_iam_member.preview_commit_transition_coordinator.member, "serviceAccount:")],
      [google_service_account_iam_member.prod_deploy_uses_runtime.role == "roles/iam.serviceAccountUser"],
      [google_service_account_iam_member.preview_deploy_uses_preview_runtime.role == "roles/iam.serviceAccountUser"],
    ))
    error_message = "Federated principals may be granted only to service accounts, never directly on project or bucket resources, and no binding may create tokens."
  }
}

run "transition_sha_binds_only_transition_eligible_workflows" {
  command = plan

  variables {
    transition_workflow_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }

  assert {
    condition = keys(google_service_account_iam_member.workflow_authority) == [
      "gha-deploy-parity/.github/workflows/deploy-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-deploy-parity/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-commit/.github/workflows/cleanup-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-commit/.github/workflows/cleanup-preview.yml@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "gha-preview-commit/.github/workflows/deploy-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-commit/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-commit/.github/workflows/reconcile-previews.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-commit/.github/workflows/reconcile-previews.yml@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "gha-preview-deploy/.github/workflows/deploy-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-deploy/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-operator/.github/workflows/cleanup-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-operator/.github/workflows/cleanup-preview.yml@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "gha-preview-operator/.github/workflows/deploy-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-operator/.github/workflows/reconcile-previews.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-preview-operator/.github/workflows/reconcile-previews.yml@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "gha-preview-publish/.github/workflows/deploy-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-prod-deploy/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-prod-publish/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-terraform/.github/workflows/infrastructure.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-wif-canary/.github/workflows/cleanup-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-wif-canary/.github/workflows/cleanup-preview.yml@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "gha-wif-canary/.github/workflows/deploy-preview.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-wif-canary/.github/workflows/deploy-prod.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-wif-canary/.github/workflows/infrastructure.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-wif-canary/.github/workflows/reconcile-previews.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "gha-wif-canary/.github/workflows/reconcile-previews.yml@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ]
    error_message = "A transition SHA must add exactly the six preview-operations bindings to the twenty active ones."
  }

  assert {
    condition = length([
      for key in keys(google_service_account_iam_member.workflow_authority) : key
      if endswith(key, "@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") && (strcontains(key, "deploy-prod.yml") || strcontains(key, "deploy-preview.yml") || strcontains(key, "infrastructure.yml"))
    ]) == 0
    error_message = "A predecessor token must never deploy, publish, or converge infrastructure."
  }

  assert {
    condition     = google_service_account_iam_member.workflow_authority["gha-preview-operator/.github/workflows/reconcile-previews.yml@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"].member == "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.job_workflow_ref/collinbentley1/platform/.github/workflows/reconcile-previews.yml@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    error_message = "Transition members must name the transition SHA on the exact workflow path."
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
