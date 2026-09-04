mock_provider "google" {}

variables {
  repository_id             = "1255553151"
  active_workflow_sha       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  transition_workflow_sha   = ""
  legacy_compatibility_mode = false
}

run "reject_pre_migration_active_sha" {
  command = plan

  variables {
    active_workflow_sha = "734d0cd02187f88c6e91263f127dc3f4c0709feb"
  }

  expect_failures = [var.active_workflow_sha]
}

run "reject_pre_migration_transition_sha" {
  command = plan

  variables {
    transition_workflow_sha = "4f032955477c26b942fdd4f1b01f5272380390ea"
  }

  expect_failures = [var.transition_workflow_sha]
}

run "reject_legacy_compatibility_mode" {
  command = plan

  variables {
    legacy_compatibility_mode = true
  }

  expect_failures = [var.legacy_compatibility_mode]
}

run "steady_state_passes_no_transition_sha" {
  command = plan

  assert {
    condition     = local.transition_workflow_sha == null
    error_message = "An empty transition input must reach the module as null, so no transition binding exists at steady state."
  }
}

run "repin_passes_the_previous_sha_as_the_transition" {
  command = plan

  variables {
    transition_workflow_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }

  assert {
    condition     = local.transition_workflow_sha == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    error_message = "The immediately previous reviewed SHA must reach the module as the one optional transition SHA."
  }
}
