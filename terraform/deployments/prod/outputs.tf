output "artifact_registry_repository" {
  description = "Artifact Registry Docker repository."
  value       = module.site.artifact_registry_repository
}

output "preview_artifact_registry_repository" {
  description = "Artifact Registry Docker repository reserved for previews."
  value       = module.site.preview_artifact_registry_repository
}

output "cloud_run_service_name" {
  description = "Production Cloud Run service name."
  value       = module.site.cloud_run_service_name
}

output "cloud_run_service_uri" {
  description = "Production Cloud Run service URL."
  value       = module.site.cloud_run_service_uri
}

output "preview_cloud_run_service_name" {
  description = "Shared Cloud Run preview service name."
  value       = module.site.preview_cloud_run_service_name
}
