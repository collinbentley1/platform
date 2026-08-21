output "cloud_run_domain_mappings" {
  description = "Production Cloud Run custom-domain DNS records."
  value       = module.domains.dns_records
}
