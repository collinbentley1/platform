output "cloud_run_domain_mappings" {
  description = "Production Cloud Run custom-domain DNS records."
  value       = module.domains.dns_records
}

output "preview_domain_dns_records" {
  description = "Critical History wildcard preview and certificate-authorization DNS records; null for other repositories."
  value       = var.repository_id == "280932482" ? module.preview_domain["preview.ycriticalhistory.org"].dns_records : null
}

output "preview_url_pattern" {
  description = "Critical History stable pull request preview URL pattern; null for other repositories."
  value       = var.repository_id == "280932482" ? module.preview_domain["preview.ycriticalhistory.org"].preview_url_pattern : null
}
