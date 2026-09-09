mock_provider "google" {}

override_data {
  target = data.google_project.current
  values = {
    number = "894875537243"
  }
}

variables {
  app                                                    = "virtual-care-mcp"
  project_id                                             = "virtual-care-mcp"
  region                                                 = "us-east4"
  state_bucket_name                                      = "virtual-care-mcp-tfstate"
  bootstrap_state_bucket_name                            = "virtual-care-mcp-tfstate-bootstrap"
  state_bucket_location                                  = "US-EAST4"
  github_owner                                           = "collinbentley1"
  github_repo                                            = "virtual-care-mcp"
  github_repository_id                                   = "1362801465"
  active_workflow_sha                                    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  federation_quarantined                                 = true
  manage_automatic_default_service_account_grants_policy = false
  runtime_project_roles                                  = ["roles/datastore.user"]
}

run "isolated_enrollment_keeps_federation_disabled_and_iam_local" {
  command = plan

  assert {
    condition     = google_iam_workload_identity_pool.github.disabled
    error_message = "Initial enrollment must keep the new workload identity pool disabled."
  }

  assert {
    condition = local.preview_iam_auditor_members == toset([
      "serviceAccount:gha-preview-operator@virtual-care-mcp.iam.gserviceaccount.com",
    ])
    error_message = "The new project must grant the preview auditor role only to its own identity."
  }

  assert {
    condition     = keys(google_project_iam_member.runtime_project_roles) == ["roles/datastore.user"]
    error_message = "Production runtime data authority must be exactly the reviewed Firestore role."
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github.attribute_condition == "google.subject.startsWith('16823277:1362801465:github-hosted:')"
    error_message = "The new pool must admit only the exact new repository identity."
  }
}

run "legacy_auditor_memberships_remain_the_same_four_identities" {
  command = plan

  variables {
    app                  = "cdbentley"
    project_id           = "cdbentley"
    github_repo          = "cdbentley"
    github_repository_id = "1255553151"
  }

  assert {
    condition = local.preview_iam_auditor_members == toset([
      "serviceAccount:gha-preview-operator@cdbentley.iam.gserviceaccount.com",
      "serviceAccount:gha-preview-operator@critical-history-16823277.iam.gserviceaccount.com",
      "serviceAccount:gha-preview-operator@medlock-1025243085.iam.gserviceaccount.com",
      "serviceAccount:gha-preview-operator@runsetta.iam.gserviceaccount.com",
    ])
    error_message = "Adding the new app must not alter the existing four-project auditor group."
  }
}
