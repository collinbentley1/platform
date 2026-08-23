mock_provider "google" {}

run "reject_pre_migration_active_sha" {
  command = plan

  variables {
    repository_id             = "1255553151"
    active_workflow_sha       = "734d0cd02187f88c6e91263f127dc3f4c0709feb"
    transition_workflow_sha   = ""
    legacy_compatibility_mode = true
  }

  expect_failures = [var.active_workflow_sha]
}

run "reject_pre_migration_transition_sha" {
  command = plan

  variables {
    repository_id             = "1255553151"
    active_workflow_sha       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    transition_workflow_sha   = "4f032955477c26b942fdd4f1b01f5272380390ea"
    legacy_compatibility_mode = true
  }

  expect_failures = [var.transition_workflow_sha]
}

run "steady_state_partitions_preview_operations_to_active" {
  command = plan

  variables {
    repository_id             = "1255553151"
    active_workflow_sha       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    transition_workflow_sha   = ""
    legacy_compatibility_mode = false
  }

  assert {
    condition     = local.preview_operations_active_workflow_shas == toset(["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"])
    error_message = "The active preview-operations set must contain only the active workflow SHA."
  }

  assert {
    condition     = length(local.preview_operator_transition_workflow_shas) == 0
    error_message = "The retired preview-operator transition set must be empty at steady state."
  }
}

run "migration_partitions_previous_preview_operator_sha" {
  command = plan

  variables {
    repository_id             = "1255553151"
    active_workflow_sha       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    transition_workflow_sha   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    legacy_compatibility_mode = false
  }

  assert {
    condition     = local.preview_operations_active_workflow_shas == toset(["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"])
    error_message = "The new workflow SHA must authenticate preview operations through the preview deploy identity."
  }

  assert {
    condition     = local.preview_operator_transition_workflow_shas == toset(["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"])
    error_message = "Only the immediately previous SHA may retain the retired preview operator during migration."
  }
}

run "reject_transition_sha_with_legacy_compatibility_bindings" {
  command = plan

  variables {
    repository_id             = "1255553151"
    active_workflow_sha       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    transition_workflow_sha   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    legacy_compatibility_mode = true
  }

  expect_failures = [var.legacy_compatibility_mode]
}
