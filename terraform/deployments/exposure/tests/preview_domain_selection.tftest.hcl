mock_provider "google" {}

run "critical_history_gets_stable_preview_routing" {
  command = plan

  variables {
    repository_id = "280932482"
  }

  assert {
    condition     = length(module.preview_domain) == 1
    error_message = "Critical History must receive exactly one stable preview-domain router."
  }

  assert {
    condition     = module.preview_domain["preview.ycriticalhistory.org"].preview_url_pattern == "https://pr-N.preview.ycriticalhistory.org"
    error_message = "Critical History must expose only the fixed pr-N.preview.ycriticalhistory.org pattern."
  }

  assert {
    condition     = output.preview_domain_dns_records != null && output.preview_url_pattern == "https://pr-N.preview.ycriticalhistory.org"
    error_message = "Critical History root outputs must fail closed and expose its reviewed DNS and URL contract."
  }
}

run "other_repositories_get_no_preview_routing" {
  command = plan

  variables {
    repository_id = "1255553151"
  }

  assert {
    condition     = length(module.preview_domain) == 0
    error_message = "Stable Critical History preview routing must not be created in another application project."
  }

  assert {
    condition     = output.preview_url_pattern == null
    error_message = "Non-Critical repositories must not expose a stable preview URL pattern."
  }

  assert {
    condition     = output.preview_domain_dns_records == null
    error_message = "Non-Critical repositories must not emit preview-domain DNS records."
  }
}
