output "state_bucket_name" {
  description = "Routine production Terraform state bucket."
  value       = google_storage_bucket.terraform_state.name
}

output "bootstrap_state_bucket_name" {
  description = "Separately protected privileged bootstrap Terraform state bucket."
  value       = google_storage_bucket.bootstrap_state.name
}

output "workload_identity_provider" {
  description = "Full Workload Identity Provider resource name for GitHub Actions."
  value       = "projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.github.workload_identity_pool_id}/providers/${google_iam_workload_identity_pool_provider.github.workload_identity_pool_provider_id}"
}

output "terraform_service_account_email" {
  description = "Metadata-only service account used by the Terraform convergence workflow."
  value       = google_service_account.terraform.email
}

output "prod_deploy_service_account_email" {
  description = "Cloud Run deploy service account with read-only access to the exact production image repository."
  value       = google_service_account.prod_deploy.email
}

output "prod_publisher_service_account_email" {
  description = "Artifact Registry-only service account used by the production publish job."
  value       = google_service_account.prod_publisher.email
}

output "preview_deploy_service_account_email" {
  description = "Cloud Run deploy service account with read-only access to the exact preview image repository."
  value       = google_service_account.preview_deploy.email
}

output "preview_operator_service_account_email" {
  description = "Cloud Run traffic-only service account used by preview cleanup and reconciliation jobs."
  value       = google_service_account.preview_operator.email
}

output "preview_publisher_service_account_email" {
  description = "Artifact Registry-only service account used by the preview publish job."
  value       = google_service_account.preview_publisher.email
}

output "exact_wif_canary_service_account_email" {
  description = "No-privilege service account used to prove exact workflow-SHA WIF bindings."
  value       = google_service_account.exact_wif_canary.email
}

output "cloud_run_revision_deployer_role" {
  description = "Custom role for updating pre-created Cloud Run services without delete access."
  value       = google_project_iam_custom_role.cloud_run_revision_deployer.name
}

output "terraform_convergence_reader_role" {
  description = "Custom metadata-only role used by the routine production convergence plan."
  value       = google_project_iam_custom_role.terraform_convergence_reader.name
}

output "runtime_service_account_email" {
  description = "Cloud Run runtime service account."
  value       = google_service_account.runtime.email
}

output "preview_runtime_service_account_email" {
  description = "No-data Cloud Run runtime service account for pull request previews."
  value       = google_service_account.preview_runtime.email
}

output "bootstrap_runtime_service_account_email" {
  description = "No-role Cloud Run identity used by the initial bootstrap image."
  value       = google_service_account.bootstrap_runtime.email
}
