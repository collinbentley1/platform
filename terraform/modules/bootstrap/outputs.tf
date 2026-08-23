output "state_bucket_name" {
  description = "Routine production Terraform state bucket."
  value       = google_storage_bucket.terraform_state.name
}

output "bootstrap_state_bucket_name" {
  description = "Separately protected privileged bootstrap Terraform state bucket."
  value       = google_storage_bucket.bootstrap_state.name
}

output "deployment_parity_transition_bucket_name" {
  description = "Dedicated PAP/UBLA bucket containing the single strongly consistent deployment parity transition marker."
  value       = google_storage_bucket.deployment_parity_transition.name
}

output "deployment_parity_transition_object_name" {
  description = "Pre-created object whose custom metadata is the generation/metageneration-CASed transition state."
  value       = google_storage_bucket_object.deployment_parity_transition.name
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
  description = "Cloud Run deploy service account with read-only access to the exact production image repository and only declared exact-secret version-add grants."
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

output "preview_commit_service_account_email" {
  description = "Exact-workflow transaction identity scoped to preview traffic and exposure changes only."
  value       = google_service_account.preview_commit.email
}

output "preview_iam_audit_service_account_email" {
  description = "Exact-workflow, read-only cross-project preview runtime IAM auditor."
  value       = google_service_account.preview_operator.email
}

output "preview_operator_service_account_email" {
  description = "Retired transition-only preview operator service account; receives no steady-state operational grants."
  value       = google_service_account.preview_operator.email
}

output "preview_publisher_service_account_email" {
  description = "Artifact Registry-only service account used by the preview publish job."
  value       = google_service_account.preview_publisher.email
}

output "deployment_parity_reader_service_account_email" {
  description = "Exact-workflow, read-only identity for production-image and Cloud Run DHI parity checks."
  value       = google_service_account.deployment_parity_reader.email
}

output "exact_wif_canary_service_account_email" {
  description = "No-privilege service account used to prove exact workflow-SHA WIF bindings."
  value       = google_service_account.exact_wif_canary.email
}

output "cloud_run_revision_deployer_role" {
  description = "Custom role for updating pre-created Cloud Run services without delete access."
  value       = google_project_iam_custom_role.cloud_run_revision_deployer.name
}

output "preview_traffic_committer_role" {
  description = "Preview-service-scoped custom role for exact traffic and exposure transactions."
  value       = google_project_iam_custom_role.preview_traffic_committer.name
}

output "deployment_parity_transition_coordinator_role" {
  description = "Exact-object role containing only storage.objects.get and storage.objects.update."
  value       = google_project_iam_custom_role.deployment_parity_transition_coordinator.name
}

output "preview_iam_auditor_role" {
  description = "Project-scoped custom role for IAM analysis and direct project-policy brackets only."
  value       = google_project_iam_custom_role.preview_iam_auditor.name
}

output "deployment_parity_cloud_run_reader_role" {
  description = "Service-scoped custom role containing only run.services.get and run.revisions.get."
  value       = google_project_iam_custom_role.deployment_parity_cloud_run_reader.name
}

output "deployment_parity_image_downloader_role" {
  description = "Repository-scoped custom role containing only artifactregistry.repositories.downloadArtifacts."
  value       = google_project_iam_custom_role.deployment_parity_image_downloader.name
}

output "preview_traffic_image_downloader_role" {
  description = "Transition-only custom role definition retained until old preview-operator grants converge away."
  value       = google_project_iam_custom_role.preview_traffic_image_downloader.name
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
