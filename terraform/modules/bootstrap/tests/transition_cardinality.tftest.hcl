mock_provider "google" {}

run "reject_multiple_preview_operator_transition_shas" {
  command = plan

  variables {
    app                         = "example"
    project_id                  = "example"
    region                      = "us-east4"
    state_bucket_name           = "example-tfstate"
    bootstrap_state_bucket_name = "example-bootstrap-tfstate"
    state_bucket_location       = "US-EAST4"
    github_owner                = "collinbentley1"
    github_repo                 = "example"
    github_owner_id             = "16823277"
    github_repository_id        = "123456789"
    trusted_platform_workflow_shas = [
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "cccccccccccccccccccccccccccccccccccccccc",
    ]
    preview_operations_active_workflow_shas = [
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]
    preview_operator_transition_workflow_shas = [
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "cccccccccccccccccccccccccccccccccccccccc",
    ]
    legacy_compatibility_mode                              = true
    manage_automatic_default_service_account_grants_policy = false
  }

  expect_failures = [var.preview_operator_transition_workflow_shas]
}

run "reject_any_transition_sha_with_legacy_mutator_bindings" {
  command = plan

  variables {
    app                         = "example"
    project_id                  = "example"
    region                      = "us-east4"
    state_bucket_name           = "example-tfstate"
    bootstrap_state_bucket_name = "example-bootstrap-tfstate"
    state_bucket_location       = "US-EAST4"
    github_owner                = "collinbentley1"
    github_repo                 = "example"
    github_owner_id             = "16823277"
    github_repository_id        = "123456789"
    trusted_platform_workflow_shas = [
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ]
    preview_operations_active_workflow_shas = [
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]
    preview_operator_transition_workflow_shas = [
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ]
    legacy_compatibility_mode                              = true
    manage_automatic_default_service_account_grants_policy = false
  }

  expect_failures = [var.legacy_compatibility_mode]
}
