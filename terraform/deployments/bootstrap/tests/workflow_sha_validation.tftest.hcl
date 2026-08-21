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
